// The test environment has no modal dialogs of its own. These stand in
// for them: a dialog that was shown is open, one that was closed is not.

HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
  this.setAttribute("open", "");
};
HTMLDialogElement.prototype.show = HTMLDialogElement.prototype.showModal;
HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
  this.removeAttribute("open");
  this.dispatchEvent(new Event("close"));
};
