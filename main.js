/* egresstop — main entry point. Same pattern as siblings. */

import { RingBuf } from "yeet:bpf";
import bpf from "./bin/egresstop.bpf.o";

import { onEvent, advance, TICK_MS } from "./state.js";
import { renderDashboard, clearScreen } from "./dashboard.js";

const HIDE = "\x1b[?25l";
const SHOW = "\x1b[?25h";

const tty = globalThis.tty;
if (!tty) {
  console.error("egresstop: no tty available (yeet didn't expose globalThis.tty)");
  throw new Error("missing tty");
}

let cols = 100, rows = 36;
function readSize() {
  const sz = tty.size?.();
  if (sz) { cols = sz.cols ?? cols; rows = sz.rows ?? rows; }
}
readSize();
tty.on?.("resize", () => { readSize(); paint(); });

function paint() {
  const frame = renderDashboard(cols, rows);
  if (tty.beginFrame) {
    tty.beginFrame();
    tty.write(frame);
    tty.endFrame();
  } else {
    tty.write(frame);
  }
}

async function main() {
  tty.write(HIDE);
  tty.write(clearScreen());

  const control = await bpf
    .bind("events", { kind: "ringbuf", btf_struct: "conn_evt" })
    .start();

  await new RingBuf(control, "events").subscribe(
    (evt) => onEvent(evt.conn_evt ?? evt),
    (err) => console.error("egresstop ringbuf error:", err?.message ?? err),
  );

  setInterval(() => { advance(); paint(); }, TICK_MS);
  paint();
}

main().catch((e) => {
  tty.write(SHOW);
  console.error(e?.stack ?? e?.message ?? e);
});
