<script>
  import { Chart, registerables } from 'chart.js';
  import { bandwidthHistory } from '$lib/stores/stats.js';

  Chart.register(...registerables);

  let canvasEl = $state(null);
  let chart = $state(null);

  function formatBytes(bytes) {
    if (bytes >= 1_048_576) return (bytes / 1_048_576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  }

  $effect(() => {
    if (!canvasEl) return;

    chart = new Chart(canvasEl, {
      type: 'line',
      data: {
        labels: Array.from({ length: 60 }, (_, i) => `${60 - i}s`),
        datasets: [{
          data: [],
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0, 212, 255, 0.1)',
          fill: true,
          pointRadius: 0,
          borderWidth: 1.5,
          tension: 0.3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 0 },
        plugins: {
          legend: { display: false },
        },
        scales: {
          x: {
            grid: { color: '#1a1a2e' },
            ticks: { color: '#666', maxTicksLimit: 6, font: { size: 10 } },
          },
          y: {
            grid: { color: '#1a1a2e' },
            ticks: {
              color: '#666',
              font: { size: 10 },
              callback: (val) => formatBytes(Number(val)),
            },
            beginAtZero: true,
          },
        },
      },
    });

    return () => {
      chart?.destroy();
    };
  });

  $effect(() => {
    const data = $bandwidthHistory;
    if (!chart) return;
    const padded = Array.from({ length: 60 }, (_, i) => {
      const idx = i - (60 - data.length);
      return idx >= 0 ? data[idx] : 0;
    });
    chart.data.datasets[0].data = padded;
    chart.update('none');
  });
</script>

<div class="bandwidth-chart">
  <div class="chart-title">Bandwidth (bytes/sec)</div>
  <div class="chart-container">
    <canvas bind:this={canvasEl}></canvas>
  </div>
</div>

<style>
  .bandwidth-chart {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .chart-title {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 8px 10px 4px;
  }

  .chart-container {
    flex: 1;
    padding: 0 10px 10px;
    min-height: 0;
    position: relative;
  }
</style>
