<script>
  import { invoke } from '@tauri-apps/api/core';
  import { hasPermission } from '$lib/stores/capture.js';

  let checking = $state(false);

  async function checkPerms() {
    checking = true;
    try {
      const result = await invoke('check_permissions');
      hasPermission.set(result);
    } catch {
      hasPermission.set(false);
    } finally {
      checking = false;
    }
  }

  $effect(() => {
    checkPerms();
  });
</script>

<div class="permission-overlay">
  <div class="permission-card">
    <div class="icon">&#x1f6e1;</div>
    <h2>BPF Permissions Required</h2>
    <p>Wirehound needs access to BPF devices to capture packets.</p>

    <div class="instructions">
      <h3>Quick Fix (temporary)</h3>
      <code>sudo chmod o+r /dev/bpf*</code>

      <h3>Permanent Fix</h3>
      <code>sudo dscl . -append /dev/bpf0 AccessControl everyone allow read</code>
      <p class="hint">Or add your user to the <strong>access_bpf</strong> group if available.</p>
    </div>

    <button onclick={checkPerms} disabled={checking}>
      {checking ? 'Checking...' : 'Check Again'}
    </button>
  </div>
</div>

<style>
  .permission-overlay {
    position: fixed;
    inset: 0;
    background: #0a0a0f;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .permission-card {
    background: #1a1a2e;
    border: 1px solid #2a2a4a;
    border-radius: 12px;
    padding: 40px;
    max-width: 520px;
    text-align: center;
    color: #e0e0e0;
  }

  .icon {
    font-size: 48px;
    margin-bottom: 16px;
  }

  h2 {
    color: #00d4ff;
    margin: 0 0 12px;
    font-size: 22px;
  }

  h3 {
    color: #aaa;
    font-size: 14px;
    margin: 20px 0 8px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .instructions {
    text-align: left;
    margin: 24px 0;
  }

  code {
    display: block;
    background: #0a0a0f;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 13px;
    color: #00d4ff;
    user-select: all;
  }

  .hint {
    font-size: 12px;
    color: #888;
    margin-top: 8px;
  }

  button {
    margin-top: 20px;
    background: #00d4ff;
    color: #0a0a0f;
    border: none;
    border-radius: 6px;
    padding: 10px 28px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
  }

  button:hover {
    opacity: 0.85;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
