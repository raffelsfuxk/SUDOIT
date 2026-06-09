#!/usr/bin/env python3
"""
SUDOIT Beacon Flood Detection Module
Detect excessive beacon frames indicating flood attacks.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import defaultdict

from scapy.all import sniff, Dot11, Dot11Beacon

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class BeaconFloodDetector:
    """
    Beacon Flood Attack Detector.
    
    Monitors for abnormal beacon frame rates which may
    indicate a beacon flood attack designed to confuse
    wireless clients or hide rogue APs.
    
    Features:
        - Real-time beacon rate monitoring
        - Per-BSSID tracking
        - Abnormal rate detection
        - SSID flood detection (many fake SSIDs)
        - Alert system
        - Statistical analysis
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._callback: Optional[Callable] = None
        self._alerts: List[Dict] = []
        self._beacon_count: Dict[str, int] = defaultdict(int)
        self._ssid_count: Dict[str, int] = defaultdict(int)
        self._bssid_info: Dict[str, Dict] = {}
        self._start_time = None
        self._total_beacons = 0
    
    def set_callback(self, callback: Callable):
        """Set callback for real-time alerts."""
        self._callback = callback
    
    def detect(self, beacon_threshold: int = 50,
               ssid_threshold: int = 100,
               interval: int = 10,
               duration: int = 60) -> Dict:
        """
        Detect beacon flood attacks.
        
        Args:
            beacon_threshold: Max beacons per BSSID per interval
            ssid_threshold: Max unique SSIDs per interval
            interval: Check interval in seconds
            duration: Total monitoring time
        
        Returns:
            Dict with detection results
        """
        self.logger.info(f"Beacon flood detection started (threshold={beacon_threshold}/{interval}s)")
        self.running = True
        self._start_time = time.time()
        self._alerts.clear()
        self._beacon_count.clear()
        self._ssid_count.clear()
        self._total_beacons = 0
        
        print(f"\n[*] Beacon Flood Detection Active")
        print(f"    Beacon Threshold: {beacon_threshold}/{interval}s")
        print(f"    SSID Threshold:   {ssid_threshold}/{interval}s")
        print(f"    Duration:         {duration}s")
        print(f"    Press Ctrl+C to stop\n")
        
        last_check = time.time()
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    if not bssid:
                        return
                    
                    self._beacon_count[bssid] += 1
                    self._total_beacons += 1
                    
                    # Track BSSID info
                    if bssid not in self._bssid_info:
                        self._bssid_info[bssid] = {
                            "first_seen": datetime.now().isoformat(),
                            "total_beacons": 0
                        }
                    self._bssid_info[bssid]["total_beacons"] += 1
                    self._bssid_info[bssid]["last_seen"] = datetime.now().isoformat()
                    
                    # Check threshold periodically
                    nonlocal last_check
                    current = time.time()
                    if current - last_check >= interval:
                        self._check_beacon_threshold(beacon_threshold, interval)
                        self._check_ssid_threshold(ssid_threshold, interval)
                        self._beacon_count.clear()
                        self._ssid_count.clear()
                        last_check = current
                        
            except Exception as e:
                self.logger.debug(f"Packet error: {e}")
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0,
                timeout=duration
            )
        except Exception as e:
            self.logger.error(f"Detection error: {e}")
        finally:
            self.running = False
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        print(f"\n[*] Detection Complete")
        print(f"    Total Beacons: {self._total_beacons}")
        print(f"    Unique BSSIDs: {len(self._bssid_info)}")
        print(f"    Alerts:        {len(self._alerts)}")
        print(f"    Duration:      {elapsed:.1f}s")
        
        return self.get_results()
    
    def _check_beacon_threshold(self, threshold: int, interval: int):
        """Check if any BSSID exceeds beacon threshold."""
        for bssid, count in self._beacon_count.items():
            if count > threshold:
                alert = {
                    "type": "BEACON_FLOOD",
                    "bssid": bssid,
                    "beacon_count": count,
                    "threshold": threshold,
                    "interval": interval,
                    "timestamp": datetime.now().isoformat()
                }
                
                self._alerts.append(alert)
                
                print(f"  [!] BEACON FLOOD: {bssid} - {count} beacons/{interval}s")
                
                if self._callback:
                    self._callback(alert)
    
    def _check_ssid_threshold(self, threshold: int, interval: int):
        """Check if too many unique SSIDs (SSID flood)."""
        if len(self._ssid_count) > threshold:
            alert = {
                "type": "SSID_FLOOD",
                "ssid_count": len(self._ssid_count),
                "threshold": threshold,
                "interval": interval,
                "timestamp": datetime.now().isoformat()
            }
            
            self._alerts.append(alert)
            
            print(f"  [!] SSID FLOOD: {len(self._ssid_count)} unique SSIDs/{interval}s")
            
            if self._callback:
                self._callback(alert)
    
    def get_results(self) -> Dict:
        """Get detection results and statistics."""
        # Top beacon sources
        top_sources = sorted(
            self._bssid_info.items(),
            key=lambda x: x[1]['total_beacons'],
            reverse=True
        )[:10]
        
        # Calculate average beacon rate
        elapsed = time.time() - self._start_time if self._start_time else 1
        avg_rate = self._total_beacons / elapsed if elapsed > 0 else 0
        
        return {
            "total_beacons": self._total_beacons,
            "unique_bssids": len(self._bssid_info),
            "alerts": self._alerts.copy(),
            "alert_count": len(self._alerts),
            "avg_beacon_rate": round(avg_rate, 2),
            "top_sources": [
                {"bssid": bssid, **info}
                for bssid, info in top_sources
            ],
            "duration": elapsed
        }
    
    def get_top_sources(self, top_n: int = 10) -> List[Dict]:
        """Get top beacon sources by count."""
        sorted_sources = sorted(
            self._bssid_info.items(),
            key=lambda x: x[1]['total_beacons'],
            reverse=True
        )
        return [
            {"bssid": bssid, **info}
            for bssid, info in sorted_sources[:top_n]
        ]
    
    def get_alert_summary(self) -> Dict:
        """Get summary of all alerts."""
        alert_types = defaultdict(int)
        for alert in self._alerts:
            alert_types[alert.get('type', 'UNKNOWN')] += 1
        
        return {
            "total_alerts": len(self._alerts),
            "alert_types": dict(alert_types),
            "first_alert": self._alerts[0]['timestamp'] if self._alerts else None,
            "last_alert": self._alerts[-1]['timestamp'] if self._alerts else None
        }
    
    def export_results(self, filepath: str):
        """Export detection results to JSON."""
        import json
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "results": self.get_results(),
            "top_sources": self.get_top_sources(20),
            "alert_summary": self.get_alert_summary()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[✓] Results exported: {filepath}")
        self.logger.info(f"Results exported: {filepath}")
    
    def stop(self):
        """Stop detection."""
        self.running = False
        self.logger.info("Beacon flood detection stopped")
    
    def is_running(self) -> bool:
        """Check if detector is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "running": self.running,
            "total_beacons": self._total_beacons,
            "unique_bssids": len(self._bssid_info),
            "alerts": len(self._alerts),
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
