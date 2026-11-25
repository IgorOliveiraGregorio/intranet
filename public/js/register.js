import { register } from './api.js';
import { normalizePhone, validateRegister } from './validators.js';
import { bindPasswordToggles, clearErrors, setBusy, showAlert, showFieldErrors } from './ui.js';

const form = document.getElementById('register-form');
const alertEl = document.getElementById('alert');
const submit = document.getElementById('submit');

bindPasswordToggles();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearErrors(form, alertEl);

  const values = {
    username: form.username.value.trim(),
    email: form.email.value.trim(),
    phone: form.phone.value,
    password: form.password.value,
    confirm: form.confirm.value,
  };
  if (showFieldErrors(form, validateRegister(values))) return;

  setBusy(submit, true, 'Criando conta…');
  try {
    await register({
      username: values.username,
      email: values.email,
      phone: normalizePhone(values.phone),
      password: values.password,
    });
    location.assign('/login?registered=1');
  } catch (err) {
    // 400/409: erros por campo vindos do servidor (inclui duplicidade de usuário/e-mail)
    const shown = err.details ? showFieldErrors(form, err.details) : false;
    if (!shown) showAlert(alertEl, err.message);
    setBusy(submit, false);
  }
});
