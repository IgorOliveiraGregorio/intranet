import { login } from './api.js';
import { validateLogin } from './validators.js';
import { bindPasswordToggles, clearErrors, setBusy, showAlert, showFieldErrors } from './ui.js';

const form = document.getElementById('login-form');
const alertEl = document.getElementById('alert');
const submit = document.getElementById('submit');
const notice = document.getElementById('notice');

bindPasswordToggles();

if (new URLSearchParams(location.search).get('registered') === '1') {
  notice.textContent = 'Conta criada com sucesso. Entre com seus dados.'; // texto fixo, nada refletido da URL
  notice.hidden = false;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearErrors(form, alertEl);

  const values = { username: form.username.value.trim(), password: form.password.value };
  if (showFieldErrors(form, validateLogin(values))) return;

  setBusy(submit, true, 'Entrando…');
  try {
    await login(values);
    location.assign('/dashboard');
  } catch (err) {
    // Mensagem do servidor é genérica ("Usuário ou senha inválidos."): não revela se a conta existe.
    showAlert(alertEl, err.message);
    form.password.value = '';
    form.password.focus();
    setBusy(submit, false);
  }
});
