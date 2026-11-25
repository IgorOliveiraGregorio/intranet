// Helpers de interface. Todo texto dinâmico entra via textContent (nunca innerHTML) => sem XSS.

export function clearErrors(form, alertEl) {
  for (const input of form.elements) {
    if (!input.name) continue;
    input.removeAttribute('aria-invalid');
    const slot = document.getElementById(`${input.name}-error`);
    if (slot) slot.textContent = '';
  }
  if (alertEl) alertEl.hidden = true;
}

/** Mostra erros por campo e foca o primeiro inválido. Retorna true se havia erros. */
export function showFieldErrors(form, errors) {
  let first = null;
  for (const [name, message] of Object.entries(errors)) {
    const input = form.elements[name];
    const slot = document.getElementById(`${name}-error`);
    if (!input || !slot) continue; // erros sem campo vão para o alerta geral
    input.setAttribute('aria-invalid', 'true');
    slot.textContent = message;
    first ??= input;
  }
  first?.focus();
  return first !== null;
}

export function showAlert(el, message) {
  el.textContent = message;
  el.hidden = false;
}

export function setBusy(button, busy, busyLabel) {
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = busyLabel;
  } else if (button.dataset.label) {
    button.textContent = button.dataset.label;
  }
  button.disabled = busy;
}

/** Botões "Mostrar/Ocultar" de senha. */
export function bindPasswordToggles() {
  for (const btn of document.querySelectorAll('[data-toggle-for]')) {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.toggleFor);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Ocultar' : 'Mostrar';
      btn.setAttribute('aria-pressed', String(show));
    });
  }
}
