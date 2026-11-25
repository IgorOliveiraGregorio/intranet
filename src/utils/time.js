'use strict';

/** Timestamp atual em segundos (padrão usado em sessões e claims JWT). */
const nowSeconds = () => Math.floor(Date.now() / 1000);

module.exports = { nowSeconds };
