import * as htmx from 'htmx.org';
import {showErrorToast} from './modules/toast.js';
import 'htmx.org/dist/ext/ws.js';

// https://github.com/bigskysoftware/idiomorph#htmx
import 'idiomorph/dist/idiomorph-ext.js';

// https://htmx.org/reference/#config
htmx.config.requestClass = 'is-loading';
htmx.config.scrollIntoViewOnBoost = false;

// https://htmx.org/events/#htmx:sendError
document.body.addEventListener('htmx:sendError', (e) => {
  // TODO: add translations
  showErrorToast(`Network error when calling ${e.detail.requestConfig.path}`);
});

// https://htmx.org/events/#htmx:responseError
document.body.addEventListener('htmx:responseError', (e) => {
  // TODO: add translations
  showErrorToast(`Error ${e.detail.xhr.status} when calling ${e.detail.requestConfig.path}`);
});

// TODO: move websocket creation to SharedWorker by overriding htmx.createWebSocket

document.body.addEventListener('htmx:wsOpen', (e) => {
  const socket = e.detail.socketWrapper;
  socket.send(
    JSON.stringify({action: 'subscribe', data: {url: window.location.href}}),
  );
});
