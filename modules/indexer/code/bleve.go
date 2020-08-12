// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package code

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/analyze"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/charset"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/modules/util"

	"github.com/blevesearch/bleve"
	analyzer_custom "github.com/blevesearch/bleve/analysis/analyzer/custom"
	analyzer_keyword "github.com/blevesearch/bleve/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/analysis/token/lowercase"
	"github.com/blevesearch/bleve/analysis/token/unicodenorm"
	"github.com/blevesearch/bleve/analysis/tokenizer/unicode"
	"github.com/blevesearch/bleve/index/upsidedown"
	"github.com/blevesearch/bleve/mapping"
	"github.com/blevesearch/bleve/search/query"
	"github.com/ethantkoenig/rupture"
	"github.com/go-enry/go-enry/v2"
)

const unicodeNormalizeName = "unicodeNormalize"
const maxBatchSize = 16

// indexerID a bleve-compatible unique identifier for an integer id
func indexerID(id int64) string {
	return strconv.FormatInt(id, 36)
}

// numericEqualityQuery a numeric equality query for the given value and field
func numericEqualityQuery(value int64, field string) *query.NumericRangeQuery {
	f := float64(value)
	tru := true
	q := bleve.NewNumericRangeInclusiveQuery(&f, &f, &tru, &tru)
	q.SetField(field)
	return q
}

func addUnicodeNormalizeTokenFilter(m *mapping.IndexMappingImpl) error {
	return m.AddCustomTokenFilter(unicodeNormalizeName, map[string]interface{}{
		"type": unicodenorm.Name,
		"form": unicodenorm.NFC,
	})
}

// openIndexer open the index at the specified path, checking for metadata
// updates and bleve version updates.  If index needs to be created (or
// re-created), returns (nil, nil)
func openIndexer(path string, latestVersion int) (bleve.Index, error) {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	metadata, err := rupture.ReadIndexMetadata(path)
	if err != nil {
		return nil, err
	}
	if metadata.Version < latestVersion {
		// the indexer is using a previous version, so we should delete it and
		// re-populate
		return nil, util.RemoveAll(path)
	}

	index, err := bleve.Open(path)
	if err != nil && err == upsidedown.IncompatibleVersion {
		// the indexer was built with a previous version of bleve, so we should
		// delete it and re-populate
		return nil, util.RemoveAll(path)
	} else if err != nil {
		return nil, err
	}
	return index, nil
}

// RepoIndexerData data stored in the repo indexer
type RepoIndexerData struct {
	RepoID    int64
	CommitID  string
	Content   string
	Language  string
	UpdatedAt time.Time
}

// Type returns the document type, for bleve's mapping.Classifier interface.
func (d *RepoIndexerData) Type() string {
	return repoIndexerDocType
}

func addUpdate(commitSha string, update fileUpdate, repo *models.Repository, batch rupture.FlushingBatch) error {
	// Ignore vendored files in code search
	if setting.Indexer.ExcludeVendored && enry.IsVendor(update.Filename) {
		return nil
	}
	stdout, err := git.NewCommand("cat-file", "-s", update.BlobSha).
		RunInDir(repo.RepoPath())
	if err != nil {
		return err
	}
	if size, err := strconv.Atoi(strings.TrimSpace(stdout)); err != nil {
		return fmt.Errorf("Misformatted git cat-file output: %v", err)
	} else if int64(size) > setting.Indexer.MaxIndexerFileSize {
		return addDelete(update.Filename, repo, batch)
	}

	fileContents, err := git.NewCommand("cat-file", "blob", update.BlobSha).
		RunInDirBytes(repo.RepoPath())
	if err != nil {
		return err
	} else if !base.IsTextFile(fileContents) {
		// FIXME: UTF-16 files will probably fail here
		return nil
	}

	id := filenameIndexerID(repo.ID, update.Filename)
	return batch.Index(id, &RepoIndexerData{
		RepoID:    repo.ID,
		CommitID:  commitSha,
		Content:   string(charset.ToUTF8DropErrors(fileContents)),
		Language:  analyze.GetCodeLanguage(update.Filename, fileContents),
		UpdatedAt: time.Now().UTC(),
	})
}

func addDelete(filename string, repo *models.Repository, batch rupture.FlushingBatch) error {
	id := filenameIndexerID(repo.ID, filename)
	return batch.Delete(id)
}

const (
	repoIndexerAnalyzer      = "repoIndexerAnalyzer"
	repoIndexerDocType       = "repoIndexerDocType"
	repoIndexerLatestVersion = 5
)

// createRepoIndexer create a repo indexer if one does not already exist
func createRepoIndexer(path string, latestVersion int) (bleve.Index, error) {
	docMapping := bleve.NewDocumentMapping()
	numericFieldMapping := bleve.NewNumericFieldMapping()
	numericFieldMapping.IncludeInAll = false
	docMapping.AddFieldMappingsAt("RepoID", numericFieldMapping)

	textFieldMapping := bleve.NewTextFieldMapping()
	textFieldMapping.IncludeInAll = false
	docMapping.AddFieldMappingsAt("Content", textFieldMapping)

	termFieldMapping := bleve.NewTextFieldMapping()
	termFieldMapping.IncludeInAll = false
	termFieldMapping.Analyzer = analyzer_keyword.Name
	docMapping.AddFieldMappingsAt("Language", termFieldMapping)
	docMapping.AddFieldMappingsAt("CommitID", termFieldMapping)

	timeFieldMapping := bleve.NewDateTimeFieldMapping()
	timeFieldMapping.IncludeInAll = false
	docMapping.AddFieldMappingsAt("UpdatedAt", timeFieldMapping)

	mapping := bleve.NewIndexMapping()
	if err := addUnicodeNormalizeTokenFilter(mapping); err != nil {
		return nil, err
	} else if err := mapping.AddCustomAnalyzer(repoIndexerAnalyzer, map[string]interface{}{
		"type":          analyzer_custom.Name,
		"char_filters":  []string{},
		"tokenizer":     unicode.Name,
		"token_filters": []string{unicodeNormalizeName, lowercase.Name},
	}); err != nil {
		return nil, err
	}
	mapping.DefaultAnalyzer = repoIndexerAnalyzer
	mapping.AddDocumentMapping(repoIndexerDocType, docMapping)
	mapping.AddDocumentMapping("_all", bleve.NewDocumentDisabledMapping())

	indexer, err := bleve.New(path, mapping)
	if err != nil {
		return nil, err
	}

	if err = rupture.WriteIndexMetadata(path, &rupture.IndexMetadata{
		Version: latestVersion,
	}); err != nil {
		return nil, err
	}
	return indexer, nil
}

func filenameIndexerID(repoID int64, filename string) string {
	return indexerID(repoID) + "_" + filename
}

func filenameOfIndexerID(indexerID string) string {
	index := strings.IndexByte(indexerID, '_')
	if index == -1 {
		log.Error("Unexpected ID in repo indexer: %s", indexerID)
	}
	return indexerID[index+1:]
}

var (
	_ Indexer = &BleveIndexer{}
)

// BleveIndexer represents a bleve indexer implementation
type BleveIndexer struct {
	indexDir string
	indexer  bleve.Index
}

// NewBleveIndexer creates a new bleve local indexer
func NewBleveIndexer(indexDir string) (*BleveIndexer, bool, error) {
	indexer := &BleveIndexer{
		indexDir: indexDir,
	}
	created, err := indexer.init()
	return indexer, created, err
}

// init init the indexer
func (b *BleveIndexer) init() (bool, error) {
	var err error
	b.indexer, err = openIndexer(b.indexDir, repoIndexerLatestVersion)
	if err != nil {
		return false, err
	}
	if b.indexer != nil {
		return false, nil
	}

	b.indexer, err = createRepoIndexer(b.indexDir, repoIndexerLatestVersion)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Close close the indexer
func (b *BleveIndexer) Close() {
	log.Debug("Closing repo indexer")
	if b.indexer != nil {
		err := b.indexer.Close()
		if err != nil {
			log.Error("Error whilst closing the repository indexer: %v", err)
		}
	}
	log.Info("PID: %d Repository Indexer closed", os.Getpid())
}

// Index indexes the data
func (b *BleveIndexer) Index(repoID int64) error {
	repo, err := models.GetRepositoryByID(repoID)
	if err != nil {
		return err
	}

	sha, err := getDefaultBranchSha(repo)
	if err != nil {
		return err
	}
	changes, err := getRepoChanges(repo, sha)
	if err != nil {
		return err
	} else if changes == nil {
		return nil
	}

	batch := rupture.NewFlushingBatch(b.indexer, maxBatchSize)
	for _, update := range changes.Updates {
		if err := addUpdate(sha, update, repo, batch); err != nil {
			return err
		}
	}
	for _, filename := range changes.RemovedFilenames {
		if err := addDelete(filename, repo, batch); err != nil {
			return err
		}
	}
	if err = batch.Flush(); err != nil {
		return err
	}
	return repo.UpdateIndexerStatus(models.RepoIndexerTypeCode, sha)
}

// Delete deletes indexes by ids
func (b *BleveIndexer) Delete(repoID int64) error {
	query := numericEqualityQuery(repoID, "RepoID")
	searchRequest := bleve.NewSearchRequestOptions(query, 2147483647, 0, false)
	result, err := b.indexer.Search(searchRequest)
	if err != nil {
		return err
	}
	batch := rupture.NewFlushingBatch(b.indexer, maxBatchSize)
	for _, hit := range result.Hits {
		if err = batch.Delete(hit.ID); err != nil {
			return err
		}
	}
	return batch.Flush()
}

// Search searches for files in the specified repo.
// Returns the matching file-paths
func (b *BleveIndexer) Search(repoIDs []int64, language, keyword string, page, pageSize int) (int64, []*SearchResult, []*SearchResultLanguages, error) {
	phraseQuery := bleve.NewMatchPhraseQuery(keyword)
	phraseQuery.FieldVal = "Content"
	phraseQuery.Analyzer = repoIndexerAnalyzer

	var indexerQuery query.Query
	if len(repoIDs) > 0 {
		var repoQueries = make([]query.Query, 0, len(repoIDs))
		for _, repoID := range repoIDs {
			repoQueries = append(repoQueries, numericEqualityQuery(repoID, "RepoID"))
		}

		indexerQuery = bleve.NewConjunctionQuery(
			bleve.NewDisjunctionQuery(repoQueries...),
			phraseQuery,
		)
	} else {
		indexerQuery = phraseQuery
	}

	// Save for reuse without language filter
	facetQuery := indexerQuery
	if len(language) > 0 {
		languageQuery := bleve.NewMatchQuery(language)
		languageQuery.FieldVal = "Language"
		languageQuery.Analyzer = analyzer_keyword.Name

		indexerQuery = bleve.NewConjunctionQuery(
			indexerQuery,
			languageQuery,
		)
	}

	from := (page - 1) * pageSize
	searchRequest := bleve.NewSearchRequestOptions(indexerQuery, pageSize, from, false)
	searchRequest.Fields = []string{"Content", "RepoID", "Language", "CommitID", "UpdatedAt"}
	searchRequest.IncludeLocations = true

	if len(language) == 0 {
		searchRequest.AddFacet("languages", bleve.NewFacetRequest("Language", 10))
	}

	result, err := b.indexer.Search(searchRequest)
	if err != nil {
		return 0, nil, nil, err
	}

	total := int64(result.Total)

	searchResults := make([]*SearchResult, len(result.Hits))
	for i, hit := range result.Hits {
		var startIndex, endIndex int = -1, -1
		for _, locations := range hit.Locations["Content"] {
			location := locations[0]
			locationStart := int(location.Start)
			locationEnd := int(location.End)
			if startIndex < 0 || locationStart < startIndex {
				startIndex = locationStart
			}
			if endIndex < 0 || locationEnd > endIndex {
				endIndex = locationEnd
			}
		}
		language := hit.Fields["Language"].(string)
		var updatedUnix timeutil.TimeStamp
		if t, err := time.Parse(time.RFC3339, hit.Fields["UpdatedAt"].(string)); err == nil {
			updatedUnix = timeutil.TimeStamp(t.Unix())
		}
		searchResults[i] = &SearchResult{
			RepoID:      int64(hit.Fields["RepoID"].(float64)),
			StartIndex:  startIndex,
			EndIndex:    endIndex,
			Filename:    filenameOfIndexerID(hit.ID),
			Content:     hit.Fields["Content"].(string),
			CommitID:    hit.Fields["CommitID"].(string),
			UpdatedUnix: updatedUnix,
			Language:    language,
			Color:       enry.GetColor(language),
		}
	}

	searchResultLanguages := make([]*SearchResultLanguages, 0, 10)
	if len(language) > 0 {
		// Use separate query to go get all language counts
		facetRequest := bleve.NewSearchRequestOptions(facetQuery, 1, 0, false)
		facetRequest.Fields = []string{"Content", "RepoID", "Language", "CommitID", "UpdatedAt"}
		facetRequest.IncludeLocations = true
		facetRequest.AddFacet("languages", bleve.NewFacetRequest("Language", 10))

		if result, err = b.indexer.Search(facetRequest); err != nil {
			return 0, nil, nil, err
		}

	}
	languagesFacet := result.Facets["languages"]
	for _, term := range languagesFacet.Terms {
		if len(term.Term) == 0 {
			continue
		}
		searchResultLanguages = append(searchResultLanguages, &SearchResultLanguages{
			Language: term.Term,
			Color:    enry.GetColor(term.Term),
			Count:    term.Count,
		})
	}
	return total, searchResults, searchResultLanguages, nil
}
