<script>
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import { packets, selectedPacket } from '$lib/stores/packets.js';
  import { stats, bandwidthHistory } from '$lib/stores/stats.js';
  import { hasPermission, isCapturing } from '$lib/stores/capture.js';

  import PermissionCheck from '$lib/components/PermissionCheck.svelte';
  import Toolbar from '$lib/components/Toolbar.svelte';
  import PacketList from '$lib/components/PacketList.svelte';
  import PacketDetail from '$lib/components/PacketDetail.svelte';
  import BandwidthChart from '$lib/components/BandwidthChart.svelte';
  import ProtocolChart from '$lib/components/ProtocolChart.svelte';

  import '../app.css';

  let detailHeight = $state(250);
  let chartsWidth = $state(320);
  let resizingDetail = $state(false);
  let resizingCharts = $state(false);
  let captureError = $state('');

  onMount(() => {
    const unlisteners = [];

    listen('packet', (event) => {
      packets.add(event.payload);
    }).then(u => unlisteners.push(u));

    listen('stats', (event) => {
      stats.set(event.payload);
      bandwidthHistory.push(event.payload.bytes_per_sec);
    }).then(u => unlisteners.push(u));

    listen('capture-error', (event) => {
      captureError = String(event.payload);
      isCapturing.set(false);
      setTimeout(() => { captureError = ''; }, 8000);
    }).then(u => unlisteners.push(u));

    return () => {
      unlisteners.forEach(u => u());
    };
  });

  function startDetailResize(e) {
    e.preventDefault();
    resizingDetail = true;
    const startY = e.clientY;
    const startHeight = detailHeight;

    function onMove(ev) {
      detailHeight = Math.max(100, Math.min(600, startHeight - (ev.clientY - startY)));
    }
    function onUp() {
      resizingDetail = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }

  function startChartsResize(e) {
    e.preventDefault();
    resizingCharts = true;
    const startX = e.clientX;
    const startWidth = chartsWidth;

    function onMove(ev) {
      chartsWidth = Math.max(200, Math.min(600, startWidth - (ev.clientX - startX)));
    }
    function onUp() {
      resizingCharts = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }
</script>

{#if $hasPermission === false}
  <PermissionCheck />
{:else}
  <div class="app-layout">
    <Toolbar />

    {#if captureError}
      <div class="capture-error">
        Capture error: {captureError}
      </div>
    {/if}

    <div class="content-area">
      <div class="packet-area">
        <PacketList />
      </div>

      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="resize-handle-v" onmousedown={startChartsResize}></div>

      <div class="charts-area" style="width: {chartsWidth}px; min-width: {chartsWidth}px">
        <div class="chart-slot">
          <BandwidthChart />
        </div>
        <div class="chart-slot">
          <ProtocolChart />
        </div>
      </div>
    </div>

    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="resize-handle-h" onmousedown={startDetailResize}></div>

    <div class="detail-area" style="height: {detailHeight}px; min-height: {detailHeight}px">
      <PacketDetail />
    </div>
  </div>
{/if}

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
    background: #0a0a0f;
  }

  .capture-error {
    background: #e5737330;
    color: #e57373;
    padding: 6px 12px;
    font-size: 13px;
    border-bottom: 1px solid #e5737350;
  }

  .content-area {
    flex: 1;
    display: flex;
    min-height: 0;
    overflow: hidden;
  }

  .packet-area {
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }

  .charts-area {
    display: flex;
    flex-direction: column;
    background: #0d0d18;
    border-left: 1px solid #2a2a4a;
    overflow: hidden;
  }

  .chart-slot {
    flex: 1;
    min-height: 0;
    border-bottom: 1px solid #2a2a4a;
  }

  .chart-slot:last-child {
    border-bottom: none;
  }

  .detail-area {
    border-top: 1px solid #2a2a4a;
    overflow: hidden;
  }

  .resize-handle-h {
    height: 4px;
    cursor: ns-resize;
    background: #2a2a4a;
    flex-shrink: 0;
    transition: background 0.15s;
  }

  .resize-handle-h:hover {
    background: #00d4ff;
  }

  .resize-handle-v {
    width: 4px;
    cursor: ew-resize;
    background: #2a2a4a;
    flex-shrink: 0;
    transition: background 0.15s;
  }

  .resize-handle-v:hover {
    background: #00d4ff;
  }
</style>
