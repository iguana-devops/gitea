import $ from 'jquery';

let ariaIdCounter = 0;

function generateAriaId() {
  return `_aria_auto_id_${ariaIdCounter++}`;
}

function attachOneDropdownAria($dropdown) {
  if ($dropdown.attr('data-aria-attached')) return;
  $dropdown.attr('data-aria-attached', 1);

  // Dropdown has 2 different focusing behaviors
  // * with search input: the input is focused, and it works with aria-activedescendant pointing another sibling element.
  // * without search input (but the readonly text), the dropdown itself is focused. then the aria-activedescendant points to the element inside dropdown
  // Some desktop screen readers may change the focus, but dropdown requires that the focus must be on its primary element, then they don't work well.

  // Expected user interactions for dropdown with aria support:
  // * user can use Tab to focus in the dropdown, then the dropdown menu (list) will be shown
  // * user presses Tab on the focused dropdown to move focus to next sibling focusable element (but not the menu item)
  // * user can use arrow key Up/Down to navigate between menu items
  // * when user presses Enter:
  //    - if the menu item is clickable (eg: <a>), then trigger the click event
  //    - otherwise, the dropdown control (low-level code) handles the Enter event, hides the dropdown menu

  const $textSearch = $dropdown.find('input.search').eq(0);
  const $focusable = $textSearch.length ? $textSearch : $dropdown; // the primary element for focus, see comment above
  if (!$focusable.length) return;

  // detect if the dropdown has an input, if yes, it works like a combobox, otherwise it works like a menu
  // or use a special class to indicate it's a combobox/menu in the future
  const isComboBox = $dropdown.find('input').length > 0;

  const focusableRole = isComboBox ? 'combobox' : 'button';
  const listPopupRole = isComboBox ? 'listbox' : 'menu';
  const listItemRole = isComboBox ? 'option' : 'menuitem';

  // make the item has role=option/menuitem, and add an id if there wasn't one yet.
  function prepareMenuItem($item) {
    if (!$item.attr('id')) $item.attr('id', generateAriaId());
    $item.attr({'role': listItemRole, 'tabindex': '-1'});
    $item.find('a').attr('tabindex', '-1'); // as above, the elements inside the dropdown menu item should not be focusable, the focus should always be on the dropdown primary element.
  }

  const dropdownTemplates = $dropdown.dropdown('setting', 'templates');
  const dropdownTemplatesMenuOld = dropdownTemplates.menu;
  dropdownTemplates.menu = function(response, fields, preserveHTML, className) {
    // when the dropdown menu items are loaded from AJAX requests, the items are created dynamically
    const ret = dropdownTemplatesMenuOld(response, fields, preserveHTML, className);
    const $wrapper = $('<div>').append(ret);
    const $items = $wrapper.find('> .item');
    $items.each((_, item) => {
      prepareMenuItem($(item));
    });
    return $wrapper.html();
  };
  $dropdown.dropdown('setting', ['templates', dropdownTemplates]);


  // TODO: multiple selection is not supported yet.

  // use tooltip's content as aria-label if there is no aria-label
  if ($dropdown.hasClass('tooltip') && $dropdown.attr('data-content') && !$dropdown.attr('aria-label')) {
    $dropdown.attr('aria-label', $dropdown.attr('data-content'));
  }

  // prepare dropdown menu list popup
  const $menu = $dropdown.find('> .menu');
  if (!$menu.attr('id')) $menu.attr('id', generateAriaId());
  $menu.attr('role', listPopupRole);
  $menu.find('> .item').each((_, item) => {
    prepareMenuItem($(item));
  });

  $focusable.attr({
    'role': focusableRole,
    'aria-haspopup': listPopupRole,
    'aria-controls': $menu.attr('id'),
    'aria-expanded': 'false',
  });

  // update aria attributes according to current active/selected item
  const refreshAria = () => {
    const isMenuVisible = !$menu.is('.hidden') && !$menu.is('.animating.out');
    $focusable.attr('aria-expanded', isMenuVisible ? 'true' : 'false');

    let $active = $menu.find('> .item.active');
    if (!$active.length) $active = $menu.find('> .item.selected'); // it's strange that we need this fallback at the moment

    // if there is an active item, use its id. if no active item, then the empty string is set
    $focusable.attr('aria-activedescendant', $active.attr('id'));
  };

  $dropdown.on('keydown', (e) => {
    // here it must use keydown event before dropdown's keyup handler, otherwise there is no Enter event in our keyup handler
    if (e.key === 'Enter') {
      let $item = $dropdown.dropdown('get item', $dropdown.dropdown('get value'));
      if (!$item) $item = $menu.find('> .item.selected'); // when dropdown filters items by input, there is no "value", so query the "selected" item
      // if the selected item is clickable, then trigger the click event.
      // we can not click any item without check, because Fomantic code might also handle the Enter event. that would result in double click.
      if ($item && ($item.is('a') || $item.hasClass('js-aria-clickable'))) $item[0].click();
    }
  });

  // use setTimeout to run the refreshAria in next tick (to make sure the Fomantic UI code has finished its work)
  const deferredRefreshAria = () => { setTimeout(refreshAria, 0) }; // do not return any value, jQuery has return-value related behaviors.
  $focusable.on('focus', deferredRefreshAria);
  $focusable.on('mouseup', deferredRefreshAria);
  $focusable.on('blur', deferredRefreshAria);
  $dropdown.on('keyup', (e) => { if (e.key.startsWith('Arrow')) deferredRefreshAria(); });
}

export function attachDropdownAria($dropdowns) {
  $dropdowns.each((_, e) => attachOneDropdownAria($(e)));
}

export function attachCheckboxAria($checkboxes) {
  $checkboxes.checkbox();

  // Fomantic UI checkbox needs to be something like: <div class="ui checkbox"><label /><input /></div>
  // It doesn't work well with <label><input />...</label>
  // To make it work with aria, the "id"/"for" attributes are necessary, so add them automatically if missing.
  // In the future, refactor to use native checkbox directly, then this patch could be removed.
  for (const el of $checkboxes) {
    const label = el.querySelector('label');
    const input = el.querySelector('input');
    if (!label || !input || input.getAttribute('id')) continue;
    const id = generateAriaId();
    input.setAttribute('id', id);
    label.setAttribute('for', id);
  }
}
