import { getMe, logout, logoutAll } from './api.js';
import { showAlert } from './ui.js';

const $ = (id) => document.getElementById(id);
const alertEl = $('alert');

function render(user) {
  $('greeting').textContent = `Olá, ${user.username}`;
  $('p-username').textContent = user.username;
  $('p-email').textContent = user.email;
  $('p-phone').textContent = user.phone;
  $('p-created').textContent = new Date(user.createdAt).toLocaleDateString('pt-BR', { dateStyle: 'long' });
  $('profile-section').hidden = false;
  $('security-section').hidden = false;
  $('logout').disabled = false;
}

async function leave(action) {
  try {
    await action();
  } finally {
    location.replace('/login');
  }
}

$('logout').addEventListener('click', () => leave(logout));
$('logout-all').addEventListener('click', () => leave(logoutAll));

try {
  // Sem token em memória, getMe() renova a sessão pelo cookie HttpOnly e tenta de novo.
  render(await getMe());
} catch (err) {
  if (err.status === 401) {
    location.replace('/login');
  } else {
    $('greeting').textContent = 'Painel';
    showAlert(alertEl, err.message);
  }
}
