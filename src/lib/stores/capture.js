import { writable } from 'svelte/store';

/** @type {import('svelte/store').Writable<any[]>} */
export const interfaces = writable([]);

export const selectedInterface = writable('');
export const bpfFilter = writable('');
export const isCapturing = writable(false);

/** @type {import('svelte/store').Writable<boolean | null>} */
export const hasPermission = writable(null);

export const displayFilter = writable('');
