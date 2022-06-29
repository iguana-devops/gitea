import $ from 'jquery';

const {csrfToken} = window.config;

async function uploadFile(file, uploadUrl, dropzone) {
  const formData = new FormData();
  formData.append('file', file, file.name);

  const res = await fetch(uploadUrl, {
    method: 'POST',
    headers: {'X-Csrf-Token': csrfToken},
    body: formData,
  });
  const data = await res.json();
  const upfile = {name: file.name, size: file.size, uuid: data.uuid};
  dropzone.emit('addedfile', upfile);
  dropzone.emit('thumbnail', upfile, `/attachments/${data.uuid}`);
  dropzone.emit('complete', upfile);
  dropzone.files.push(upfile);
  return data;
}

/**
 * @param editor{EasyMDE}
 * @param fileUuid
 */
export function removeUploadedFileFromEditor(editor, fileUuid) {
  // the raw regexp is: /!\[[^\]]*]\(\/attachments\/{uuid}\)/
  const re = new RegExp(`!\\[[^\\]]*]\\(/attachments/${fileUuid}\\)`);
  editor.value(editor.value().replace(re, '')); // at the moment, we assume the editor is an EasyMDE
  if (editor.element) {
    // when using "simple textarea" mode, the value of the textarea should be replaced too.
    editor.element.value = editor.element.value.replace(re, '');
  }
}

function clipboardPastedImages(e) {
  if (!e.clipboardData) return [];

  const files = [];
  for (const item of e.clipboardData.items || []) {
    if (!item.type || !item.type.startsWith('image/')) continue;
    files.push(item.getAsFile());
  }
  return files;
}

class TextareaEditor {
  constructor(editor) {
    this.editor = editor;
  }

  insertPlaceholder(value) {
    const editor = this.editor;
    const startPos = editor.selectionStart;
    const endPos = editor.selectionEnd;
    editor.value = editor.value.substring(0, startPos) + value + editor.value.substring(endPos);
    editor.selectionStart = startPos;
    editor.selectionEnd = startPos + value.length;
    editor.focus();
  }

  replacePlaceholder(oldVal, newVal) {
    const editor = this.editor;
    const startPos = editor.selectionStart;
    const endPos = editor.selectionEnd;
    if (editor.value.substring(startPos, endPos) === oldVal) {
      editor.value = editor.value.substring(0, startPos) + newVal + editor.value.substring(endPos);
      editor.selectionEnd = startPos + newVal.length;
    } else {
      editor.value = editor.value.replace(oldVal, newVal);
      editor.selectionEnd -= oldVal.length;
      editor.selectionEnd += newVal.length;
    }
    editor.selectionStart = editor.selectionEnd;
    editor.focus();
  }
}

class CodeMirrorEditor {
  constructor(editor) {
    this.editor = editor;
  }

  insertPlaceholder(value) {
    const editor = this.editor;
    const startPoint = editor.getCursor('start');
    const endPoint = editor.getCursor('end');
    editor.replaceSelection(value);
    endPoint.ch = startPoint.ch + value.length;
    editor.setSelection(startPoint, endPoint);
    editor.focus();
  }

  replacePlaceholder(oldVal, newVal) {
    const editor = this.editor;
    const endPoint = editor.getCursor('end');
    if (editor.getSelection() === oldVal) {
      editor.replaceSelection(newVal);
    } else {
      editor.setValue(editor.getValue().replace(oldVal, newVal));
    }
    endPoint.ch -= oldVal.length;
    endPoint.ch += newVal.length;
    editor.setSelection(endPoint, endPoint);
    editor.focus();
  }
}


export function initEasyMDEImagePaste(easyMDE, $dropzone) {
  if ($dropzone.length !== 1) throw new Error('invalid dropzone binding for editor');

  const uploadUrl = $dropzone.attr('data-upload-url');
  const $files = $dropzone.find('.files');

  if (!uploadUrl || !$files.length) return;

  const uploadClipboardImage = async (editor, e) => {
    const pastedImages = clipboardPastedImages(e);
    if (!pastedImages || pastedImages.length === 0) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();

    for (const img of pastedImages) {
      const name = img.name.slice(0, img.name.lastIndexOf('.'));

      const placeholder = `![${name}](uploading ...)`;
      editor.insertPlaceholder(placeholder);
      const data = await uploadFile(img, uploadUrl, $dropzone[0].dropzone);
      editor.replacePlaceholder(placeholder, `![${name}](/attachments/${data.uuid})`);

      const $input = $(`<input name="files" type="hidden">`).attr('id', data.uuid).val(data.uuid);
      $files.append($input);
    }
  };

  easyMDE.codemirror.on('paste', async (_, e) => {
    return uploadClipboardImage(new CodeMirrorEditor(easyMDE.codemirror), e);
  });

  $(easyMDE.element).on('paste', async (e) => {
    return uploadClipboardImage(new TextareaEditor(easyMDE.element), e.originalEvent);
  });
}
