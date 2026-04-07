<script>
  import { invoke } from '@tauri-apps/api/core';
  import { interfaces, selectedInterface, bpfFilter, isCapturing, displayFilter, resolveDns } from '$lib/stores/capture.js';
  import { packets } from '$lib/stores/packets.js';
  import { bandwidthHistory, stats } from '$lib/stores/stats.js';
  import { selectedPacket } from '$lib/stores/packets.js';

  let error = $state('');

  $effect(() => {
    loadInterfaces();
  });

  async function loadInterfaces() {
    try {
      const ifaces = await invoke('list_interfaces');
      interfaces.set(ifaces);
      const nonLoopback = ifaces.find(i => !i.is_loopback);
      if (nonLoopback) {
        selectedInterface.set(nonLoopback.name);
      } else if (ifaces.length > 0) {
        selectedInterface.set(ifaces[0].name);
      }
    } catch (e) {
      error = String(e);
    }
  }

  async function toggleCapture() {
    error = '';
    if ($isCapturing) {
      try {
        await invoke('stop_capture');
        isCapturing.set(false);
      } catch (e) {
        error = String(e);
      }
    } else {
      try {
        await invoke('start_capture', {
          interfaceName: $selectedInterface,
          bpfFilter: $bpfFilter || null,
        });
        isCapturing.set(true);
      } catch (e) {
        error = String(e);
      }
    }
  }

  async function toggleDns() {
    try {
      await invoke('set_resolve_dns', { enabled: $resolveDns });
    } catch (e) {
      error = String(e);
    }
  }

  function clearPackets() {
    packets.clear();
    selectedPacket.set(null);
    bandwidthHistory.reset();
    stats.set({
      bytes_per_sec: 0,
      packets_per_sec: 0,
      protocol_breakdown: {},
      top_talkers: [],
    });
  }
</script>

<div class="toolbar">
  <div class="toolbar-group">
    <label class="toolbar-label" for="iface-select">Interface</label>
    <select
      id="iface-select"
      bind:value={$selectedInterface}
      disabled={$isCapturing}
      class="toolbar-select"
    >
      {#each $interfaces as iface}
        <option value={iface.name}>
          {iface.name}{iface.description ? ` — ${iface.description}` : ''}{iface.is_loopback ? ' (lo)' : ''}
        </option>
      {/each}
    </select>
  </div>

  <div class="toolbar-group">
    <label class="toolbar-label" for="bpf-filter">BPF Filter</label>
    <input
      id="bpf-filter"
      type="text"
      placeholder="e.g. tcp port 80"
      bind:value={$bpfFilter}
      disabled={$isCapturing}
      class="toolbar-input"
    />
  </div>

  <div class="toolbar-group">
    <label class="toolbar-label" for="display-filter">Display Filter</label>
    <input
      id="display-filter"
      type="text"
      placeholder="e.g. TCP, 192.168"
      bind:value={$displayFilter}
      class="toolbar-input"
    />
  </div>

  <div class="toolbar-actions">
    <label class="dns-toggle" title="Resolve IP addresses to hostnames via reverse DNS">
      <input
        type="checkbox"
        bind:checked={$resolveDns}
        onchange={toggleDns}
      />
      <span class="dns-label">DNS</span>
    </label>

    <button
      class="btn-capture"
      class:capturing={$isCapturing}
      onclick={toggleCapture}
    >
      {$isCapturing ? '⏹ Stop' : '▶ Start'}
    </button>

    <button
      class="btn-clear"
      onclick={clearPackets}
      disabled={$isCapturing}
    >
      Clear
    </button>

    <span class="packet-count">{$packets.length} packets</span>
  </div>

  {#if error}
    <div class="toolbar-error">{error}</div>
  {/if}
</div>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
    flex-wrap: wrap;
  }

  .toolbar-group {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .toolbar-label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
  }

  .toolbar-select,
  .toolbar-input {
    background: #0a0a0f;
    border: 1px solid #333;
    border-radius: 4px;
    color: #e0e0e0;
    padding: 4px 8px;
    font-size: 13px;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  .toolbar-select {
    min-width: 160px;
  }

  .toolbar-input {
    width: 140px;
  }

  .toolbar-select:disabled,
  .toolbar-input:disabled {
    opacity: 0.5;
  }

  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-left: auto;
  }

  .btn-capture {
    background: #00d4ff;
    color: #0a0a0f;
    border: none;
    border-radius: 4px;
    padding: 5px 16px;
    font-weight: 600;
    font-size: 13px;
    cursor: pointer;
    transition: opacity 0.2s;
  }

  .btn-capture.capturing {
    background: #e57373;
    color: #fff;
  }

  .btn-capture:hover {
    opacity: 0.85;
  }

  .btn-clear {
    background: transparent;
    border: 1px solid #444;
    color: #aaa;
    border-radius: 4px;
    padding: 5px 12px;
    font-size: 13px;
    cursor: pointer;
  }

  .btn-clear:disabled {
    opacity: 0.3;
    cursor: not-allowed;
  }

  .btn-clear:hover:not(:disabled) {
    border-color: #666;
    color: #e0e0e0;
  }

  .dns-toggle {
    display: flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    user-select: none;
  }

  .dns-toggle input {
    accent-color: #00d4ff;
    cursor: pointer;
  }

  .dns-label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .packet-count {
    font-size: 12px;
    color: #888;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  .toolbar-error {
    width: 100%;
    color: #e57373;
    font-size: 12px;
    padding: 4px 0;
  }
</style>
