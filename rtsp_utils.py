import contextlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlparse

import cv2
import numpy as np

from param import CV2_OPEN_TIMEOUT_MS, CV2_READ_TIMEOUT_MS

if os.name == "nt":
    import selectors

    def set_nonblock(fd):
        os.set_blocking(fd, False)

    def new_poller():
        return selectors.DefaultSelector()

    def poll_register(poller, fileobj):
        poller.register(fileobj, selectors.EVENT_READ)

    def poll_wait(poller, timeout):
        return poller.select(timeout)
else:
    import select
    import fcntl

    def set_nonblock(fd):
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)

    def new_poller():
        return select.poll()

    def poll_register(poller, fileobj):
        poller.register(fileobj, select.POLLIN)

    def poll_wait(poller, timeout):
        return poller.poll(timeout * 1000)



def mask_credentials(url):
    return re.sub(r"//[^@]*@", "//<hidden>@", url)


@contextlib.contextmanager
def suppress_stderr():
    with open(os.devnull, 'w') as devnull:
        stderr_fd = sys.stderr.fileno()
        saved_stderr_fd = os.dup(stderr_fd)
        os.dup2(devnull.fileno(), stderr_fd)
        try:
            yield
        finally:
            os.dup2(saved_stderr_fd, stderr_fd)
            os.close(saved_stderr_fd)


def analyze_frames(cap, duration):
    start_time = time.time()
    frames, sizes, brightness, change_levels = 0, [], [], []
    prev_gray = None
    width = height = None

    while time.time() - start_time < duration:
        ret, frame = cap.read()
        if not ret or frame is None or frame.size == 0:
            time.sleep(0.05)
            continue
        frames += 1
        sizes.append(frame.nbytes)
        height, width = frame.shape[:2]
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        brightness.append(np.mean(gray))
        if prev_gray is not None:
            delta = np.mean(np.abs(gray.astype("int16") - prev_gray.astype("int16")))
            change_levels.append(delta)
        prev_gray = gray

    return {
        "frames": frames,
        "sizes": sizes,
        "brightness": brightness,
        "change_levels": change_levels,
        "width": width,
        "height": height,
    }


def check_rtsp_stream(url, timeout=5, duration=5.0):
    result = {
        "status": "error",
        "frames_read": 0,
        "avg_frame_size_kb": 0.0,
        "width": None,
        "height": None,
        "avg_brightness": 0.0,
        "frame_change_level": 0.0,
        "real_fps": 0.0,
        "note": "Unable to determine stream resolution",
    }

    with suppress_stderr():
        cap = cv2.VideoCapture(url)
        backend = "default"
        if not cap.isOpened():
            cap.release()
            cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
            backend = "CAP_FFMPEG"

        if not cap.isOpened():
            logging.error(
                "OpenCV could not open stream %s using %s backend",
                mask_credentials(url),
                backend,
            )
            cap.release()
            cmd = [
                "ffprobe", "-v", "error",
                "-rtsp_transport", "tcp",
                "-timeout", str(int(timeout * 1e6)),
                "-i", url,
            ]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
                err_out = (p.stderr or "") + (p.stdout or "")
                err_lower = err_out.lower()
                if "401" in err_lower or "unauthorized" in err_lower or "not authorized" in err_lower:
                    return {"status": "unauthorized"}
            except Exception:
                pass
            return result

        logging.info("OpenCV using %s backend for %s", backend, mask_credentials(url))

        stats = analyze_frames(cap, duration)
        cap.release()

    frames = stats["frames"]
    width = stats["width"]
    height = stats["height"]
    if frames > 0 and width is not None and height is not None:
        result.update({
            "status": "ok",
            "frames_read": frames,
            "avg_frame_size_kb": round(sum(stats["sizes"]) / len(stats["sizes"]) / 1024, 2),
            "width": width,
            "height": height,
            "avg_brightness": round(np.mean(stats["brightness"]), 2),
            "frame_change_level": round(np.mean(stats["change_levels"]), 2) if stats["change_levels"] else 0.0,
            "real_fps": round(frames / duration, 2),
            "note": "",
        })
    else:
        result["note"] = "Unable to determine stream resolution"

    return result


def fallback_ffprobe(url, timeout=5, transport="tcp"):
    timeout_us = str(int(timeout * 1e6))
    logging.info("ffprobe stimeout=%s", timeout_us)

    base_cmd = [
        "ffprobe",
        "-v",
        "error",
        "-rtsp_transport",
        transport,
        "-i",
        url,
        "-select_streams",
        "v:0",
        "-show_entries",
        "stream=width,height,codec_name",
        "-of",
        "json",
    ]

    def _run(cmd):
        cmd_log = cmd[:-1] + [mask_credentials(cmd[-1])]
        logging.debug("Running ffprobe command: %s", " ".join(cmd_log))
        with suppress_stderr():
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)

    def _parse_process(proc):
        err_out = (proc.stderr or "") + (proc.stdout or "")
        logging.debug("ffprobe stderr: %s", err_out.strip())
        err_lower = err_out.lower()
        if "401" in err_lower or "unauthorized" in err_lower or "not authorized" in err_lower:
            return {"status": "unauthorized"}
        if "connection refused" in err_lower:
            return {"status": "refused", "error": err_out.strip() or None}
        if "stimeout" not in err_lower and (
            "timed out" in err_lower or "timeout" in err_lower
        ):
            return {"status": "timeout", "error": err_out.strip() or None}
        if "name or service not known" in err_lower or "unknown host" in err_lower:
            return {"status": "dns_fail", "error": err_out.strip() or None}
        if proc.returncode not in (0, None):
            return {"status": "error", "error": err_out.strip() or None}
        info = json.loads(proc.stdout or "{}")
        if info.get("streams"):
            stream = info["streams"][0]
            return {
                "status": "ok",
                "width": stream.get("width"),
                "height": stream.get("height"),
            }
        return {"status": "error", "error": "No streams in ffprobe output"}

    cmd_with_timeout = base_cmd[:]
    cmd_with_timeout.insert(5, "-stimeout")
    cmd_with_timeout.insert(6, timeout_us)

    try:
        proc = _run(cmd_with_timeout)
        result = _parse_process(proc)
        err_out = (proc.stderr or "") + (proc.stdout or "")
        err_lower = (err_out or "").lower()
        if (
            "stimeout" in err_lower
            and (
                "unrecognized option" in err_lower
                or "option not found" in err_lower
            )
        ):
            logging.debug("ffprobe lacks -stimeout, retrying without it")
            proc = _run(base_cmd)
            return _parse_process(proc)
        return result
    except subprocess.TimeoutExpired as exc:
        logging.error("ffprobe timeout: %s", exc)
        return {"status": "timeout", "error": str(exc)}
    except Exception as e:
        logging.error("ffprobe error: %s", e, exc_info=True)
        return {"status": "error", "error": str(e)}


def read_exact(stream, size, poller, timeout):
    data = bytearray()
    while len(data) < size:
        if not poll_wait(poller, timeout):
            break
        chunk = stream.read(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def check_rtsp_stream_with_fallback(url, timeout=5, duration=5.0):
    def _attempt(rtsp_url, transport):
        logging.info(
            "Checking RTSP URL %s with transport %s",
            mask_credentials(rtsp_url),
            transport,
        )
        attempt = {
            "transport": transport,
            "url": mask_credentials(rtsp_url),
            "path": urlparse(rtsp_url).path or "/",
            "status": "ERROR",
            "method": None,
            "note": None,
        }
        result = {
            "status": "error",
            "frames_read": 0,
            "avg_frame_size_kb": 0.0,
            "width": None,
            "height": None,
            "avg_brightness": 0.0,
            "frame_change_level": 0.0,
            "real_fps": 0.0,
            "note": "Failed to open stream",
        }
        stats = {
            "frames": 0,
            "sizes": [],
            "brightness": [],
            "change_levels": [],
            "width": None,
            "height": None,
        }
        old_opts = os.environ.get("OPENCV_FFMPEG_CAPTURE_OPTIONS")
        os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = f"rtsp_transport;{transport}"
        probe_status = None
        try:
            with suppress_stderr():
                cap = cv2.VideoCapture(rtsp_url)
                backend = "default"
                if not cap.isOpened():
                    cap.release()
                    cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
                    backend = "CAP_FFMPEG"
            if hasattr(cv2, "CAP_PROP_OPEN_TIMEOUT"):
                if not cap.set(cv2.CAP_PROP_OPEN_TIMEOUT, CV2_OPEN_TIMEOUT_MS):
                    logging.warning("Failed to set CAP_PROP_OPEN_TIMEOUT")
            else:
                logging.warning("CAP_PROP_OPEN_TIMEOUT not supported")
            if hasattr(cv2, "CAP_PROP_READ_TIMEOUT"):
                if not cap.set(cv2.CAP_PROP_READ_TIMEOUT, CV2_READ_TIMEOUT_MS):
                    logging.warning("Failed to set CAP_PROP_READ_TIMEOUT")
            else:
                logging.warning("CAP_PROP_READ_TIMEOUT not supported")

            if not cap.isOpened():
                logging.error(
                    "OpenCV could not open stream %s using %s backend",
                    mask_credentials(rtsp_url),
                    backend,
                )
                cap.release()
            else:
                logging.info(
                    "OpenCV using %s backend for %s",
                    backend,
                    mask_credentials(rtsp_url),
                )
                stats = analyze_frames(cap, duration)
                cap.release()
        finally:
            if old_opts is None:
                os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
            else:
                os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = old_opts

        if stats["frames"] > 0:
            result.update({
                "status": "ok",
                "frames_read": stats["frames"],
                "avg_frame_size_kb": round(sum(stats["sizes"]) / len(stats["sizes"]) / 1024, 2),
                "width": stats["width"],
                "height": stats["height"],
                "avg_brightness": round(np.mean(stats["brightness"]), 2),
                "frame_change_level": round(np.mean(stats["change_levels"]) if stats["change_levels"] else 0.0, 2),
                "real_fps": round(stats["frames"] / duration, 2),
                "note": "Read via OpenCV",
            })
            attempt.update({"status": "OK", "method": "opencv", "note": result["note"]})
            return result, attempt

        probe = fallback_ffprobe(rtsp_url, timeout, transport)
        probe_status = probe.get("status")
        attempt["probe_status"] = probe_status
        if probe_status == "unauthorized":
            attempt.update({"status": "UNAUTHORIZED", "method": "ffprobe", "note": probe.get("error")})
            return {"status": "unauthorized"}, attempt

        width = probe.get("width")
        height = probe.get("height")

        if width is None or height is None:
            with suppress_stderr():
                cap_dim = cv2.VideoCapture(rtsp_url)
                if not cap_dim.isOpened():
                    cap_dim.release()
                    cap_dim = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
                if cap_dim.isOpened():
                    tmp_w = int(cap_dim.get(cv2.CAP_PROP_FRAME_WIDTH))
                    tmp_h = int(cap_dim.get(cv2.CAP_PROP_FRAME_HEIGHT))
                    if tmp_w > 0 and tmp_h > 0:
                        width = width or tmp_w
                        height = height or tmp_h
                    else:
                        ret_dim, frame_dim = cap_dim.read()
                        if ret_dim and frame_dim is not None and frame_dim.size > 0:
                            height, width = frame_dim.shape[:2]
                cap_dim.release()

        result_payload = {
            "status": "error",
            "frames_read": 0,
            "avg_frame_size_kb": 0.0,
            "width": width,
            "height": height,
            "avg_brightness": 0.0,
            "frame_change_level": 0.0,
            "real_fps": 0.0,
            "note": "Unable to determine stream resolution",
        }

        if width is None or height is None:
            attempt.update({"status": "ERROR", "method": "ffprobe", "note": result_payload["note"]})
        else:
            try:
                cmd = [
                    "ffmpeg",
                    "-rtsp_transport",
                    transport,
                    "-i",
                    rtsp_url,
                    "-loglevel",
                    "error",
                    "-an",
                    "-c:v",
                    "rawvideo",
                    "-pix_fmt",
                    "bgr24",
                    "-f",
                    "rawvideo",
                    "-",
                ]
                with suppress_stderr():
                    pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=10 ** 8)

                set_nonblock(pipe.stdout.fileno())
                poller = new_poller()
                poll_register(poller, pipe.stdout)

                frames, sizes, brightness, change_levels = 0, [], [], []
                prev_gray = None
                start_time = time.time()
                expected_len = width * height * 3

                while time.time() - start_time < duration:
                    raw = read_exact(pipe.stdout, expected_len, poller, timeout)
                    actual_len = len(raw)
                    if actual_len != expected_len:
                        logging.warning(
                            "Expected frame size %d bytes, got %d", expected_len, actual_len
                        )
                        break
                    frame = np.frombuffer(raw, np.uint8).reshape((height, width, 3))
                    frames += 1
                    sizes.append(frame.nbytes)
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    brightness.append(np.mean(gray))
                    if prev_gray is not None:
                        delta = np.mean(np.abs(gray.astype("int16") - prev_gray.astype("int16")))
                        change_levels.append(delta)
                    prev_gray = gray

                poller.unregister(pipe.stdout)
                pipe.terminate()
                try:
                    pipe.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pipe.kill()
                    pipe.wait()
                stderr_data = pipe.stderr.read().decode(errors="ignore") if pipe.stderr else ""
                if pipe.stdout:
                    pipe.stdout.close()
                if pipe.stderr:
                    pipe.stderr.close()
                if "401" in stderr_data or "Unauthorized" in stderr_data:
                    attempt.update({"status": "UNAUTHORIZED", "method": "ffmpeg", "note": stderr_data.strip() or None})
                    return {"status": "unauthorized"}, attempt

                if frames > 0:
                    if stderr_data:
                        logging.warning(
                            "ffmpeg stderr for %s: %s",
                            mask_credentials(rtsp_url),
                            stderr_data.strip(),
                        )
                    result_payload.update({
                        "status": "ok",
                        "frames_read": frames,
                        "avg_frame_size_kb": round(sum(sizes) / len(sizes) / 1024, 2),
                        "width": width,
                        "height": height,
                        "avg_brightness": round(np.mean(brightness), 2),
                        "frame_change_level": round(np.mean(change_levels) if change_levels else 0.0, 2),
                        "real_fps": round(frames / duration, 2),
                        "note": "Read via ffmpeg pipe",
                    })
                    attempt.update({"status": "OK", "method": "ffmpeg", "note": result_payload["note"]})
                else:
                    logging.warning(
                        "ffmpeg produced no frames for %s",
                        mask_credentials(rtsp_url),
                    )
                    logging.warning(
                        "ffmpeg stderr for %s: %s",
                        mask_credentials(rtsp_url),
                        stderr_data.strip(),
                    )
                    result_payload["note"] = "Connected but no valid frames from ffmpeg"
                    attempt.update({"status": "ERROR", "method": "ffmpeg", "note": result_payload["note"]})

            except Exception as e:
                stderr = ""
                if "pipe" in locals() and pipe.stderr:
                    stderr = pipe.stderr.read().decode(errors="ignore")
                    logging.error(
                        "ffmpeg stderr for %s: %s",
                        mask_credentials(rtsp_url),
                        stderr.strip(),
                    )
                logging.error(
                    "ffmpeg fallback error for %s: %s",
                    mask_credentials(rtsp_url),
                    e,
                    exc_info=True,
                )
                result_payload["note"] = f"ffmpeg error: {e}"
                attempt.update({"status": "ERROR", "method": "ffmpeg", "note": result_payload["note"]})

        status_map = {
            "ok": "OK",
            "unauthorized": "UNAUTHORIZED",
            "timeout": "TIMEOUT",
            "refused": "REFUSED",
            "dns_fail": "DNS_FAIL",
        }
        if attempt["status"] in ("ERROR", None) and probe_status in status_map:
            attempt["status"] = status_map[probe_status]
            if not attempt.get("note"):
                attempt["note"] = probe.get("error")
        return result_payload, attempt

    attempts = []
    best_result = None
    best_attempt = None
    last_result = None

    for transport in ("tcp", "udp"):
        logging.info("Attempting RTSP with transport %s", transport)
        result, attempt = _attempt(url, transport)
        attempts.append(attempt)
        last_result = result
        if result.get("status") in {"ok", "unauthorized"}:
            best_result = result
            best_attempt = attempt
            break
        if best_result is None:
            best_result = result
            best_attempt = attempt

    final_result = best_result or last_result or {"status": "error"}
    final_result = dict(final_result)
    final_result.setdefault("note", "")
    final_result["attempts"] = attempts
    if best_attempt:
        final_result["best_attempt"] = best_attempt
    return final_result
