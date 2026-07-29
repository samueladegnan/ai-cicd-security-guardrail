// Minimal Chart.js mock so the renderer can render charts without the real library
global.Chart = class Chart {
  constructor(ctx, config) {
    this.ctx = ctx;
    this.config = config;
  }
  destroy() {}
};
