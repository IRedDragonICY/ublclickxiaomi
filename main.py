import subprocess
import sys
import os

# Arrays with servers
ntp_servers = [
    "ntp0.ntp-servers.net", "ntp1.ntp-servers.net", "ntp2.ntp-servers.net",
    "ntp3.ntp-servers.net", "ntp4.ntp-servers.net", "ntp5.ntp-servers.net",
    "ntp6.ntp-servers.net"
]

MI_SERVERS = ['sgp-api.buy.mi.com', '20.157.18.26']


# Installing dependencies
def install_package(package: str) -> None:
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


required_packages = [
    "requests",
    "ntplib",
    "pytz",
    "urllib3",
    "icmplib",
    "PyQt6",
    "qt-material",
    "qtawesome",
]

# Only auto-install when running inside a virtual environment
inside_venv = (
    getattr(sys, "real_prefix", None) is not None
    or sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    or os.environ.get("VIRTUAL_ENV") is not None
)

missing: list[str] = []
for package in required_packages:
    try:
        module_name = package if package != "qt-material" else "qt_material"
        __import__(module_name)
    except ImportError:
        missing.append(package)

if missing:
    if inside_venv:
        for pkg in missing:
            print(f"Installing package {pkg} in virtual environment...")
            install_package(pkg)
    else:
        print("Detected missing packages and no active virtual environment.")
        print("Please create and activate .env, then install requirements:")
        print("  python -m venv .env")
        print("  .\\.env\\Scripts\\Activate.ps1   # PowerShell")
        print("  python -m pip install -U pip")
        print("  pip install -r requirements.txt")

os.system('cls' if os.name == 'nt' else 'clear')

import hashlib
import random
import time
from datetime import datetime, timezone, timedelta
import ntplib
import pytz
import urllib3
import json
import statistics
from icmplib import ping

from PyQt6 import QtCore, QtWidgets, QtGui
from PyQt6.QtCore import QObject, QThread, pyqtSignal
from qt_material import apply_stylesheet
try:
    import qtawesome as qta  # Material/Font icons
    _HAS_QTA = True
except Exception:  # pragma: no cover
    qta = None
    _HAS_QTA = False


from typing import Optional


def debug_ping(host: str) -> Optional[float]:
    """Return avg round-trip time in ms for a host, or None if unreachable."""
    try:
        result = ping(host, count=1, interval=0.5, timeout=2, privileged=False)
        return float(result.avg_rtt) if result.is_alive else None
    except Exception as e:
        print(f"Ping error: {e}")
        return None


def get_average_ping(logger=print, stop_checker=lambda: False) -> Optional[float]:
    """Calculate average ping (ms) across MI_SERVERS, with 3 attempts each."""
    all_pings: list[float] = []
    logger("Starting ping calculation...")

    def ping_server(server: str) -> float | None:
        pings: list[float] = []
        for _ in range(3):
            if stop_checker():
                return None
            result = debug_ping(server)
            if result is not None:
                pings.append(result)
            time.sleep(0.2)
        return statistics.mean(pings) if pings else None

    for server in MI_SERVERS:
        if stop_checker():
            return None
        try:
            ping_time = ping_server(server)
            if ping_time is not None:
                all_pings.append(ping_time)
            else:
                logger(f"Failed to get ping to server {server}")
        except Exception as e:
            logger(f"Error pinging {server}: {str(e)}")

    if not all_pings:
        logger("Failed to get ping to any server! Using default value: 300 ms")
        return 300.0

    avg_ping = float(statistics.mean(all_pings))
    logger(f"Average ping: {avg_ping:.2f} ms")
    return avg_ping


def generate_device_id() -> str:
    """Generate a unique device identifier (uppercase SHA1)."""
    random_data = f"{random.random()}-{time.time()}"
    device_id = hashlib.sha1(random_data.encode('utf-8')).hexdigest().upper()
    print(f"Generated deviceId: {device_id}")
    return device_id


def get_initial_beijing_time(logger=print) -> Optional[datetime]:
    """Get current Beijing time via NTP, falling through list of servers."""
    client = ntplib.NTPClient()
    beijing_tz = pytz.timezone("Asia/Shanghai")
    for server in ntp_servers:
        try:
            logger(f"Attempting to connect to NTP server: {server}")
            response = client.request(server, version=3)
            ntp_time = datetime.fromtimestamp(response.tx_time, timezone.utc)
            beijing_time = ntp_time.astimezone(beijing_tz)
            logger(
                f"Beijing time received from server {server}: {beijing_time.strftime('%Y-%m-%d %H:%M:%S.%f')}"
            )
            return beijing_time
        except Exception as e:
            logger(f"Failed to connect to {server}: {e}")
    logger("Failed to connect to any NTP server.")
    return None


def get_synchronized_beijing_time(start_beijing_time: datetime, start_timestamp: float) -> datetime:
    elapsed = time.time() - start_timestamp
    current_time = start_beijing_time + timedelta(seconds=elapsed)
    return current_time


def wait_until_target_time(
    start_beijing_time: datetime,
    start_timestamp: float,
    ping_delay_ms: float,
    extra_delay_seconds: float,
    logger=print,
    stop_checker=lambda: False,
) -> bool:
    """Wait until next midnight (UTC+8) with network delay compensation and extra delay.

    Returns True if reached, False if stopped.
    """
    next_day = start_beijing_time + timedelta(days=1)

    network_delay = ping_delay_ms / 2.0
    server_processing_time = 30.0
    total_delay = (network_delay - server_processing_time) / 1000.0

    target_time = (
        next_day.replace(hour=0, minute=0, second=0, microsecond=0)
        - timedelta(seconds=total_delay)
        + timedelta(seconds=extra_delay_seconds)
    )

    logger(
        f"Waiting until {target_time.strftime('%Y-%m-%d %H:%M:%S.%f')} (with network compensation and extra delay)."
    )

    while True:
        if stop_checker():
            return False
        current_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
        time_diff = target_time - current_time

        if time_diff.total_seconds() > 1.0:
            time.sleep(min(1.0, time_diff.total_seconds() - 1.0))
        elif current_time >= target_time:
            logger(
                f"Time reached: {current_time.strftime('%Y-%m-%d %H:%M:%S.%f')}. Starting to send requests..."
            )
            return True
        else:
            time.sleep(0.05)


def check_unlock_status(session, cookie_value: str, device_id: str, logger=print) -> dict:
    """Check unlock status. Return structured dict with status and message."""
    try:
        url = "https://sgp-api.buy.mi.com/bbs/api/global/user/bl-switch/state"
        headers = {
            "Cookie": f"new_bbs_serviceToken={cookie_value};versionCode=500411;versionName=5.4.11;deviceId={device_id};"
        }

        response = session.make_request('GET', url, headers=headers)
        if response is None:
            logger("[Error] Failed to get unlock status.")
            return {"status": "error", "message": "Network error"}

        response_data = json.loads(response.data.decode('utf-8'))
        response.release_conn()

        if response_data.get("code") == 100004:
            logger("[Error] Cookie expired, needs to be updated!")
            return {"status": "cookie_expired", "message": "Cookie expired"}

        data = response_data.get("data", {})
        is_pass = data.get("is_pass")
        button_state = data.get("button_state")
        deadline_format = data.get("deadline_format", "")

        if is_pass == 4:
            if button_state == 1:
                logger("[Status] Account can submit an unlock request.")
                return {"status": "can_submit", "message": "OK"}
            elif button_state == 2:
                msg = f"Blocked from submitting until {deadline_format} (Month/Day)."
                logger(f"[Status] {msg}")
                return {"status": "blocked", "message": msg}
            elif button_state == 3:
                msg = "Account is less than 30 days old."
                logger(f"[Status] {msg}")
                return {"status": "too_new", "message": msg}
        elif is_pass == 1:
            msg = f"Request approved, unlock available until {deadline_format}."
            logger(f"[Status] {msg}")
            return {"status": "approved", "message": msg}

        logger("[Error] Unknown status.")
        return {"status": "unknown", "message": "Unknown status"}
    except Exception as e:
        logger(f"[Status check error] {e}")
        return {"status": "error", "message": str(e)}


def wait_until_ping_time(
    start_beijing_time: datetime,
    start_timestamp: float,
    logger=print,
    stop_checker=lambda: False,
) -> Optional[float]:
    """Wait until 23:59:30 (UTC+8) to start ping calculation. If already passed, compute immediately."""
    next_day = start_beijing_time + timedelta(days=0)
    target_time = next_day.replace(hour=23, minute=59, second=30, microsecond=0)

    logger(f"Waiting until {target_time.strftime('%Y-%m-%d %H:%M:%S')} to start ping calculation.")

    while True:
        if stop_checker():
            return None
        current_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
        time_diff = (target_time - current_time).total_seconds()

        if time_diff <= 0:
            logger(
                f"Time reached: {current_time.strftime('%Y-%m-%d %H:%M:%S')}. Starting ping calculation..."
            )
            avg_ping = get_average_ping(logger=logger, stop_checker=stop_checker)
            return avg_ping
        else:
            time.sleep(min(1.0, time_diff))


class HTTP11Session:
    """HTTP/1.1 session wrapper using urllib3 PoolManager."""

    def __init__(self):
        self.http = urllib3.PoolManager(
            maxsize=10,
            retries=True,
            timeout=urllib3.Timeout(connect=1.0, read=4.0),
            headers={},
        )

    def make_request(self, method: str, url: str, headers=None, body=None):
        try:
            request_headers = {}
            if headers:
                request_headers.update(headers)
                request_headers['Content-Type'] = 'application/json; charset=utf-8'

            if method.upper() == 'POST':
                if body is None:
                    body = '{"is_retry":true}'.encode('utf-8')
                request_headers['Content-Length'] = str(len(body))
                request_headers['Accept-Encoding'] = 'gzip, deflate, br'
                request_headers['User-Agent'] = 'okhttp/4.12.0'
                request_headers['Connection'] = 'keep-alive'

            response = self.http.request(
                method,
                url,
                headers=request_headers,
                body=body,
                preload_content=False,
            )

            return response
        except Exception as e:
            print(f"[Network error] {e}")
            return None


# ---------- Qt GUI & Threading ----------

class QtStream(QObject):
    new_text = pyqtSignal(str)

    def write(self, text: str) -> None:
        if text:
            self.new_text.emit(text)

    def flush(self) -> None:
        pass


class StatusWorker(QObject):
    finished = pyqtSignal(dict)
    log = pyqtSignal(str)

    def __init__(self, session: HTTP11Session, cookie_value: str, device_id: str):
        super().__init__()
        self.session = session
        self.cookie_value = cookie_value
        self.device_id = device_id

    def run(self):
        result = check_unlock_status(
            self.session, self.cookie_value, self.device_id, logger=lambda m: self.log.emit(str(m))
        )
        self.finished.emit(result)


class AutomationWorker(QObject):
    log = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal(str)

    def __init__(self, cookie_value: str, device_id: str, extra_delay_seconds: float):
        super().__init__()
        self.cookie_value = cookie_value
        self.device_id = device_id
        self.extra_delay_seconds = extra_delay_seconds
        self._stopped = False
        self.session = HTTP11Session()

    def stop(self):
        self._stopped = True

    def _is_stopped(self) -> bool:
        return self._stopped

    def run(self):
        logger = lambda m: self.log.emit(str(m))
        logger("Starting automation...")

        status_info = check_unlock_status(self.session, self.cookie_value, self.device_id, logger=logger)
        if status_info.get("status") != "can_submit":
            self.status.emit(status_info.get("message", "Not ready"))
            self.finished.emit("stopped")
            return

        start_beijing_time = get_initial_beijing_time(logger=logger)
        if start_beijing_time is None:
            self.status.emit("Failed to set initial Beijing time")
            self.finished.emit("error")
            return

        start_timestamp = time.time()

        avg_ping = wait_until_ping_time(
            start_beijing_time, start_timestamp, logger=logger, stop_checker=self._is_stopped
        )
        if self._is_stopped:
            self.finished.emit("stopped")
            return

        if avg_ping is None:
            logger("Using default ping: 50 ms")
            avg_ping = 50.0

        reached = wait_until_target_time(
            start_beijing_time,
            start_timestamp,
            ping_delay_ms=avg_ping,
            extra_delay_seconds=self.extra_delay_seconds,
            logger=logger,
            stop_checker=self._is_stopped,
        )
        if not reached or self._is_stopped:
            self.finished.emit("stopped")
            return

        url = "https://sgp-api.buy.mi.com/bbs/api/global/apply/bl-auth"
        headers = {
            "Cookie": f"new_bbs_serviceToken={self.cookie_value};versionCode=500411;versionName=5.4.11;deviceId={self.device_id};"
        }

        try:
            while not self._is_stopped:
                request_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
                logger(
                    f"\n[Request] Sending request at {request_time.strftime('%Y-%m-%d %H:%M:%S.%f')} (UTC+8)"
                )

                response = self.session.make_request('POST', url, headers=headers)
                if response is None:
                    continue

                response_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
                logger(
                    f"[Response] Response received at {response_time.strftime('%Y-%m-%d %H:%M:%S.%f')} (UTC+8)"
                )

                try:
                    response_data = response.data
                    response.release_conn()
                    json_response = json.loads(response_data.decode('utf-8'))
                    code = json_response.get("code")
                    data = json_response.get("data", {})

                    if code == 0:
                        apply_result = data.get("apply_result")
                        if apply_result == 1:
                            logger("[Status] Request approved, checking status...")
                            final_status = check_unlock_status(
                                self.session, self.cookie_value, self.device_id, logger=logger
                            )
                            self.status.emit(final_status.get("message", "Approved"))
                            self.finished.emit("approved")
                            return
                        elif apply_result == 3:
                            deadline_format = data.get("deadline_format", "Not specified")
                            logger(
                                f"[Status] Request not submitted, request limit reached, try again at {deadline_format} (Month/Day)."
                            )
                            self.status.emit("Limit reached")
                            self.finished.emit("limit")
                            return
                        elif apply_result == 4:
                            deadline_format = data.get("deadline_format", "Not specified")
                            logger(
                                f"[Status] Request not submitted, blocked until {deadline_format} (Month/Day)."
                            )
                            self.status.emit("Blocked")
                            self.finished.emit("blocked")
                            return
                        else:
                            logger(f"[Status] Unrecognized apply_result: {apply_result}")
                    elif code == 100001:
                        logger("[Status] Request rejected, request error.")
                        logger(f"[Full server response]: {json_response}")
                    elif code == 100003:
                        logger("[Status] Request possibly approved, checking status...")
                        logger(f"[Full server response]: {json_response}")
                        final_status = check_unlock_status(
                            self.session, self.cookie_value, self.device_id, logger=logger
                        )
                        self.status.emit(final_status.get("message", "Checked"))
                        self.finished.emit("maybe_approved")
                        return
                    elif code is not None:
                        logger(f"[Status] Unknown request status: {code}")
                        logger(f"[Full server response]: {json_response}")
                    else:
                        logger("[Error] Response does not contain the required code.")
                        logger(f"[Full server response]: {json_response}")

                except json.JSONDecodeError:
                    logger("[Error] Failed to decode JSON response.")
                    logger(f"Server response: {response_data}")
                except Exception as e:
                    logger(f"[Response processing error] {e}")
                    continue

        except Exception as e:
            logger(f"[Request error] {e}")
            self.finished.emit("error")
            return


class SettingsDialog(QtWidgets.QDialog):
    """Settings dialog for theme (Material You-style controls)."""

    def __init__(self, parent: QtWidgets.QWidget, current_mode: str, current_color: str, available_colors: list[str]):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(420, 200)

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(20, 16, 20, 16)
        main_layout.setSpacing(12)

        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
        form.setFormAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["Light", "Dark"])
        # Normalize provided mode value (e.g., "light" -> "Light")
        try:
            self.mode_combo.setCurrentText(current_mode.capitalize())
        except Exception:
            pass

        self.color_combo = QtWidgets.QComboBox()
        self.color_combo.addItems(available_colors)
        try:
            self.color_combo.setCurrentText(current_color)
        except Exception:
            pass

        form.addRow("Mode", self.mode_combo)
        form.addRow("Primary color", self.color_combo)
        main_layout.addLayout(form)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

    def selected_mode(self) -> str:
        return self.mode_combo.currentText().lower()

    def selected_color(self) -> str:
        return self.color_combo.currentText()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mi Unlock Scheduler")
        self.resize(900, 650)

        self.session = HTTP11Session()

        # Threads
        self.status_thread: Optional[QThread] = None
        self.status_worker: Optional[StatusWorker] = None
        self.automation_thread: Optional[QThread] = None
        self.automation_worker: Optional[AutomationWorker] = None
        self._ping_thread: Optional[QThread] = None
        self._ping_worker: Optional[QObject] = None

        # Theme state (Material You-like through qt-material palettes)
        self.available_colors = [
            "blue", "teal", "cyan", "red", "pink", "purple", "deep_purple",
            "indigo", "light_blue", "green", "light_green", "lime", "amber",
            "orange", "deep_orange", "brown", "blue_grey"
        ]
        self.current_mode = "light"
        self.current_color = "blue"

        # Top App Bar (Material-style)
        toolbar = QtWidgets.QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setIconSize(QtCore.QSize(20, 20))
        self.addToolBar(toolbar)

        title_label = QtWidgets.QLabel("Mi Unlock Scheduler")
        title_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        toolbar.addWidget(title_label)

        spacer = QtWidgets.QWidget()
        spacer.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Quick theme toggle (Material light/dark)
        theme_toggle_action = QtGui.QAction(
            self.get_themed_icon('mdi.theme-light-dark', QtWidgets.QStyle.StandardPixmap.SP_BrowserReload),
            "Toggle Light/Dark",
            self,
        )
        theme_toggle_action.setToolTip("Toggle theme")
        theme_toggle_action.triggered.connect(self._toggle_mode_quick)
        toolbar.addAction(theme_toggle_action)

        settings_action = QtGui.QAction(self.get_themed_icon('mdi.cog', QtWidgets.QStyle.StandardPixmap.SP_FileDialogDetailedView), "Settings", self)
        settings_action.triggered.connect(self.open_settings_dialog)
        toolbar.addAction(settings_action)
        self.settings_action = settings_action

        # UI
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        root_layout = QtWidgets.QVBoxLayout(central)
        root_layout.setContentsMargins(16, 12, 16, 12)
        root_layout.setSpacing(12)

        # Account group (card-like)
        self.account_group = QtWidgets.QGroupBox("Account")
        self.account_group.setObjectName("AccountCard")
        account_form = QtWidgets.QFormLayout(self.account_group)
        self.cookie_edit = QtWidgets.QLineEdit()
        self.cookie_edit.setPlaceholderText("Paste Xiaomi forum cookie token (new_bbs_serviceToken)")
        self.cookie_edit.setClearButtonEnabled(True)
        # Leading icon in the text field
        try:
            self.cookie_action = self.cookie_edit.addAction(
                self.get_themed_icon('mdi.cookie-outline', QtWidgets.QStyle.StandardPixmap.SP_DialogOpenButton),
                QtWidgets.QLineEdit.ActionPosition.LeadingPosition,
            )
        except Exception:
            self.cookie_action = None

        self.device_id_edit = QtWidgets.QLineEdit()
        self.device_id_edit.setReadOnly(True)
        self.device_id_edit.setText(generate_device_id())
        self.device_id_edit.setClearButtonEnabled(True)
        try:
            self.device_action = self.device_id_edit.addAction(
                self.get_themed_icon('mdi.cellphone-key', QtWidgets.QStyle.StandardPixmap.SP_DesktopIcon),
                QtWidgets.QLineEdit.ActionPosition.LeadingPosition,
            )
        except Exception:
            self.device_action = None

        self.btn_regen_device = QtWidgets.QPushButton(self.get_themed_icon('mdi.refresh', QtWidgets.QStyle.StandardPixmap.SP_BrowserReload), "Regenerate Device ID")
        self.btn_regen_device.clicked.connect(self._on_regen_device)
        device_layout = QtWidgets.QHBoxLayout()
        device_layout.addWidget(self.device_id_edit)
        device_layout.addWidget(self.btn_regen_device)
        device_wrap = QtWidgets.QWidget()
        device_wrap.setLayout(device_layout)
        account_form.addRow("Cookie token", self.cookie_edit)
        account_form.addRow("Device ID", device_wrap)
        root_layout.addWidget(self.account_group)

        # Schedule group (card-like)
        self.schedule_group = QtWidgets.QGroupBox("Schedule")
        self.schedule_group.setObjectName("ScheduleCard")
        schedule_form = QtWidgets.QGridLayout(self.schedule_group)
        self.delay_label = QtWidgets.QLabel("Extra delay seconds")
        self.delay_spin = QtWidgets.QDoubleSpinBox()
        self.delay_spin.setDecimals(1)
        self.delay_spin.setRange(0.0, 30.0)
        self.delay_spin.setSingleStep(1.0)
        self.delay_spin.setValue(0.0)
        self.delay_spin.setSuffix(" s")
        self.btn_check_status = QtWidgets.QPushButton(self.get_themed_icon('mdi.check-circle-outline', QtWidgets.QStyle.StandardPixmap.SP_DialogApplyButton), "Check Unlock Status")
        self.btn_start = QtWidgets.QPushButton(self.get_themed_icon('mdi.play', QtWidgets.QStyle.StandardPixmap.SP_MediaPlay), "Start Automation")
        self.btn_start.setProperty('isAccent', True)
        self.btn_stop = QtWidgets.QPushButton(self.get_themed_icon('mdi.stop', QtWidgets.QStyle.StandardPixmap.SP_MediaStop), "Stop")
        self.btn_stop.setEnabled(False)
        self.btn_ping_now = QtWidgets.QPushButton(self.get_themed_icon('mdi.speedometer', QtWidgets.QStyle.StandardPixmap.SP_BrowserReload), "Calculate Ping Now")
        self.btn_ping_now.clicked.connect(self._on_ping_now)
        self.btn_check_status.clicked.connect(self._on_check_status)
        self.btn_start.clicked.connect(self._on_start)
        self.btn_stop.clicked.connect(self._on_stop)

        schedule_form.addWidget(self.delay_label, 0, 0)
        schedule_form.addWidget(self.delay_spin, 0, 1)
        schedule_form.addWidget(self.btn_check_status, 0, 2)
        schedule_form.addWidget(self.btn_ping_now, 0, 3)
        schedule_form.addWidget(self.btn_start, 1, 2)
        schedule_form.addWidget(self.btn_stop, 1, 3)
        root_layout.addWidget(self.schedule_group)

        # Status and log
        self.status_label = QtWidgets.QLabel("Status: Idle")
        self.status_label.setObjectName("StatusChip")
        root_layout.addWidget(self.status_label)
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(320)
        root_layout.addWidget(self.log_view, stretch=1)

        # Redirect stdout/stderr to log view
        self.qt_stream = QtStream()
        self.qt_stream.new_text.connect(self._append_log)
        sys.stdout = self.qt_stream  # type: ignore
        sys.stderr = self.qt_stream  # type: ignore

        # Apply theme (initial)
        self.apply_theme()

        # Window app icon
        try:
            self.setWindowIcon(self.get_themed_icon('mdi.key-outline', QtWidgets.QStyle.StandardPixmap.SP_DesktopIcon))
        except Exception:
            pass

    def _append_log(self, text: str) -> None:
        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text)
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

    def _on_regen_device(self) -> None:
        self.device_id_edit.setText(generate_device_id())

    def _on_check_status(self) -> None:
        cookie = self.cookie_edit.text().strip()
        if not cookie:
            self.status_label.setText("Status: Please enter cookie")
            return
        self.status_label.setText("Status: Checking...")
        self.btn_check_status.setEnabled(False)
        self.status_thread = QThread()
        self.status_worker = StatusWorker(self.session, cookie, self.device_id_edit.text())
        self.status_worker.moveToThread(self.status_thread)
        self.status_thread.started.connect(self.status_worker.run)
        self.status_worker.log.connect(lambda m: print(m))
        self.status_worker.finished.connect(self._on_status_finished)
        self.status_worker.finished.connect(lambda _: self.status_thread.quit())
        self.status_thread.finished.connect(lambda: self.btn_check_status.setEnabled(True))
        self.status_thread.finished.connect(self.status_thread.deleteLater)
        self.status_thread.start()

    def _on_status_finished(self, result: dict) -> None:
        msg = result.get("message", "")
        self.status_label.setText(f"Status: {result.get('status')} - {msg}")

    def _on_ping_now(self) -> None:
        self.status_label.setText("Status: Calculating ping...")

        # Run ping in a simple background thread using Qt thread
        thread = QThread()

        class _PingWorker(QObject):
            done = pyqtSignal(float)
            log = pyqtSignal(str)

            def run(self_inner):
                avg = get_average_ping(logger=lambda m: self_inner.log.emit(str(m)))
                self_inner.done.emit(avg if avg is not None else -1.0)

        worker = _PingWorker()
        worker.moveToThread(thread)
        # Keep references to avoid GC
        self._ping_thread = thread
        self._ping_worker = worker
        thread.started.connect(worker.run)
        worker.log.connect(lambda m: print(m))
        worker.done.connect(lambda val: self._on_ping_done(thread, val))
        worker.done.connect(lambda _: thread.quit())
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._clear_ping_worker)
        thread.start()

    def _on_ping_done(self, thread: QThread, val: float) -> None:
        if val < 0:
            self.status_label.setText("Status: Ping failed (default 300 ms)")
        else:
            self.status_label.setText(f"Status: Average ping {val:.2f} ms")

    def _clear_ping_worker(self) -> None:
        self._ping_worker = None
        self._ping_thread = None

    def _on_start(self) -> None:
        cookie = self.cookie_edit.text().strip()
        if not cookie:
            self.status_label.setText("Status: Please enter cookie")
            return
        self._toggle_controls(False)
        self.status_label.setText("Status: Running...")
        self.automation_thread = QThread()
        self.automation_worker = AutomationWorker(
            cookie_value=cookie,
            device_id=self.device_id_edit.text(),
            extra_delay_seconds=float(self.delay_spin.value()),
        )
        self.automation_worker.moveToThread(self.automation_thread)
        self.automation_thread.started.connect(self.automation_worker.run)
        self.automation_worker.log.connect(lambda m: print(m))
        self.automation_worker.status.connect(lambda s: self.status_label.setText(f"Status: {s}"))
        self.automation_worker.finished.connect(self._on_automation_finished)
        self.automation_worker.finished.connect(lambda _: self.automation_thread.quit())
        self.automation_thread.finished.connect(self.automation_thread.deleteLater)
        self.automation_thread.start()
        self.btn_stop.setEnabled(True)

    def _on_stop(self) -> None:
        if self.automation_worker is not None:
            self.automation_worker.stop()
        self.status_label.setText("Status: Stopping...")

    def _on_automation_finished(self, reason: str) -> None:
        self._toggle_controls(True)
        self.btn_stop.setEnabled(False)
        self.status_label.setText(f"Status: Done ({reason})")

    def _toggle_controls(self, enabled: bool) -> None:
        self.cookie_edit.setEnabled(enabled)
        self.btn_check_status.setEnabled(enabled)
        self.btn_start.setEnabled(enabled)
        self.btn_regen_device.setEnabled(enabled)
        self.btn_ping_now.setEnabled(enabled)
        self.delay_spin.setEnabled(enabled)

    def open_settings_dialog(self) -> None:
        dialog = SettingsDialog(self, self.current_mode, self.current_color, self.available_colors)
        if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            self.apply_theme(mode=dialog.selected_mode(), color=dialog.selected_color())

    def apply_theme(self, mode: str | None = None, color: str | None = None) -> None:
        if mode is not None:
            self.current_mode = mode
        if color is not None:
            self.current_color = color
        theme_name = f"{self.current_mode}_{self.current_color}.xml"
        app = QtWidgets.QApplication.instance()
        if app is not None:
            try:
                # Slightly denser layout + larger corner radius
                apply_stylesheet(app, theme=theme_name, extra={
                    'density_scale': '0',
                    'corner_radius': 10,
                })
            except Exception:
                apply_stylesheet(app, theme='dark_blue.xml')
        # Overlay Material-You inspired touches
        self._apply_overlays()

        # Refresh button/icon colors when palette changes
        icon_size = QtCore.QSize(20, 20)
        for btn, spec in [
            (self.btn_check_status, ('mdi.check-circle-outline', QtWidgets.QStyle.StandardPixmap.SP_DialogApplyButton)),
            (self.btn_start, ('mdi.play', QtWidgets.QStyle.StandardPixmap.SP_MediaPlay)),
            (self.btn_stop, ('mdi.stop', QtWidgets.QStyle.StandardPixmap.SP_MediaStop)),
            (self.btn_ping_now, ('mdi.speedometer', QtWidgets.QStyle.StandardPixmap.SP_BrowserReload)),
            (self.btn_regen_device, ('mdi.refresh', QtWidgets.QStyle.StandardPixmap.SP_BrowserReload)),
        ]:
            try:
                btn.setIcon(self.get_themed_icon(*spec))
                btn.setIconSize(icon_size)
            except Exception:
                pass
        # Refresh toolbar/action icons as well
        try:
            self.settings_action.setIcon(self.get_themed_icon('mdi.cog', QtWidgets.QStyle.StandardPixmap.SP_FileDialogDetailedView))
        except Exception:
            pass
        # Refresh line-edit leading icons to keep contrast
        try:
            if getattr(self, 'cookie_action', None) is not None:
                self.cookie_action.setIcon(self.get_themed_icon('mdi.cookie-outline', QtWidgets.QStyle.StandardPixmap.SP_DialogOpenButton))
        except Exception:
            pass
        try:
            if getattr(self, 'device_action', None) is not None:
                self.device_action.setIcon(self.get_themed_icon('mdi.cellphone-key', QtWidgets.QStyle.StandardPixmap.SP_DesktopIcon))
        except Exception:
            pass

    def get_themed_icon(self, mdi_name: str, fallback: QtWidgets.QStyle.StandardPixmap) -> QtGui.QIcon:
        """Return a themed icon using qtawesome with explicit theme-aware contrast.

        Rule: Light mode → dark icons; Dark mode → white icons. Disabled state uses a
        softer gray appropriate to each mode. This avoids palette inconsistencies
        where qt-material may report light foregrounds even in Light themes.
        """
        if _HAS_QTA:
            try:
                if getattr(self, "current_mode", "light") == "light":
                    color = QtGui.QColor(33, 33, 33)
                    color_disabled = QtGui.QColor(150, 150, 150)
                else:
                    color = QtGui.QColor(255, 255, 255)
                    color_disabled = QtGui.QColor(200, 200, 200)
                return qta.icon(mdi_name, color=color, color_disabled=color_disabled)
            except Exception:
                pass
        return self.style().standardIcon(fallback)

    def _toggle_mode_quick(self) -> None:
        self.apply_theme(mode='dark' if self.current_mode == 'light' else 'light')

    def _apply_overlays(self) -> None:
        """Apply small style-sheet overlays and drop shadows for a more Material look."""
        is_light = (self.current_mode == 'light')
        # Pull key palette colors
        app = QtWidgets.QApplication.instance()
        pal = app.palette() if app else None
        primary_q = pal.highlight().color() if pal else QtGui.QColor(25, 118, 210)
        text_q = pal.windowText().color() if pal else QtGui.QColor(33, 33, 33)

        def rgba_str(c: QtGui.QColor, a: float) -> str:
            return f"rgba({c.red()}, {c.green()}, {c.blue()}, {a:.3f})"

        def hex_str(c: QtGui.QColor) -> str:
            return '#%02X%02X%02X' % (c.red(), c.green(), c.blue())

        border = 'rgba(0,0,0,0.12)' if is_light else 'rgba(255,255,255,0.12)'
        card_bg = '#FFFFFF' if is_light else '#1E1E1E'
        status_bg = rgba_str(primary_q, 0.10 if is_light else 0.18)
        outline = rgba_str(primary_q, 0.55 if is_light else 0.45)
        outline_hover = rgba_str(primary_q, 0.10 if is_light else 0.20)
        primary_hex = hex_str(primary_q)
        # Stronger title color to ensure readability in Light theme
        title_color = '#1F1F1F' if is_light else '#FAFAFA'
        accent_fg = 'white'

        overlay = f"""
        QToolBar {{
            border: none;
            padding: 4px 8px;
        }}
        QGroupBox {{
            border: 1px solid {border};
            border-radius: 14px;
            margin-top: 18px;
            padding-top: 12px;
            background: {card_bg};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 6px 10px;
            margin-left: 6px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 12px;
            letter-spacing: 0.4px;
            color: {title_color};
            background-color: {status_bg};
            border: 1px solid {border};
        }}
        QLabel#StatusChip {{
            padding: 6px 10px;
            border-radius: 10px;
            background-color: {status_bg};
        }}
        QLineEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
            border-radius: 10px;
            padding: 8px 12px;
        }}
        QPushButton {{
            border-radius: 10px;
            padding: 8px 14px;
        }}
        QPushButton[isAccent="true"] {{
            color: {accent_fg};
            background-color: palette(highlight);
        }}
        QPushButton[isAccent="true"]:disabled {{
            background-color: rgba(127,127,127,0.35);
        }}
        QPushButton[outlined="true"] {{
            background: transparent;
            border: 1px solid {outline};
            color: {primary_hex};
        }}
        QPushButton[outlined="true"]:hover {{
            background: {outline_hover};
        }}
        QPushButton[outlined="true"]:disabled {{
            border-color: rgba(127,127,127,0.35);
            color: rgba(127,127,127,0.7);
        }}
        """
        try:
            # Apply only to this window to avoid clobbering global palette
            self.setStyleSheet(overlay)
        except Exception:
            pass
        self._apply_group_shadows()

    def _apply_group_shadows(self) -> None:
        try:
            # Soft elevation shadow for cards
            shadow_color = QtGui.QColor(0, 0, 0, 60 if self.current_mode == 'light' else 100)
            def set_shadow(w: QtWidgets.QWidget):
                eff = QtWidgets.QGraphicsDropShadowEffect(w)
                eff.setBlurRadius(24)
                eff.setOffset(0, 8)
                eff.setColor(shadow_color)
                w.setGraphicsEffect(eff)
            for w in [self.account_group, self.schedule_group]:
                set_shadow(w)
        except Exception:
            pass


def run_gui_app():
    app = QtWidgets.QApplication(sys.argv)
    # Default theme (will be overridden by MainWindow.apply_theme on startup)
    apply_stylesheet(app, theme='light_blue.xml')
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui_app()