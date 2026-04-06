import { writable } from 'svelte/store';

export const stats = writable(/** @type {any} */ ({
  bytes_per_sec: 0,
  packets_per_sec: 0,
  protocol_breakdown: {},
  top_talkers: [],
}));

const MAX_HISTORY = 60;

function createBandwidthHistory() {
  const { subscribe, update, set } = writable(/** @type {number[]} */ ([]));

  return {
    subscribe,
    push(value) {
      update(arr => {
        const next = [...arr, value];
        if (next.length > MAX_HISTORY) {
          return next.slice(next.length - MAX_HISTORY);
        }
        return next;
      });
    },
    reset() {
      set([]);
    },
  };
}

export const bandwidthHistory = createBandwidthHistory();
