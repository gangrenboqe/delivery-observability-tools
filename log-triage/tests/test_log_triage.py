"""单元测试：纯函数 + 用临时文件造的小样本。不读真实日志、不联网。

运行：python -m unittest discover -s tests
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_triage import (detect_level, extract_ts, normalize, triage)


class TestNormalize(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(normalize(""), "（无错误信息）")

    def test_none(self):
        self.assertEqual(normalize(None), "（无错误信息）")

    def test_numbers_collapsed(self):
        self.assertEqual(normalize("timeout after 123ms"), normalize("timeout after 4567ms"))

    def test_uuid_masked_before_digits(self):
        """顺序陷阱：先掩码 UUID 再折叠数字，否则会得到 NbNaNbN 这种垃圾。"""
        a = normalize("user 8b1a01b6-1267-4880-97db-14147ad58fa0 failed")
        self.assertIn("<uuid>", a)
        self.assertNotIn("NbNa", a)

    def test_ip_masked(self):
        self.assertEqual(normalize("connect 10.0.0.5"), normalize("connect 192.168.1.7"))

    def test_hex_masked(self):
        self.assertEqual(normalize("id=deadbeef99"), normalize("id=cafebabe11"))

    def test_windows_path_masked(self):
        got = normalize(r"open C:\Users\Someone\secret.txt failed")
        self.assertNotIn("Someone", got)

    def test_leading_number_prefix_stripped(self):
        """行首 [123] 是线程号/错误码，去掉它同类才能真正合并。"""
        self.assertEqual(normalize("[123] Request aborted"),
                         normalize("Request aborted"))
        self.assertEqual(normalize("(42) disk error"), normalize("disk error"))

    def test_iso_t_normalized_to_space(self):
        """真实日志是 ISO 格式，T 必须换掉，否则时间跨度与按小时分布格式不一致。"""
        self.assertEqual(extract_ts("2026-10-06T02:57:03 x"), "2026-10-06 02:57:03")

    def test_length_capped(self):
        self.assertLessEqual(len(normalize("y" * 900)), 100)

    def test_whitespace_collapsed(self):
        self.assertNotIn("  ", normalize("a    b"))


class TestDetectLevel(unittest.TestCase):
    def test_english(self):
        self.assertEqual(detect_level("2026-01-01 ERROR something"), "ERROR")
        self.assertEqual(detect_level("WARN disk low"), "WARN")

    def test_fatal_beats_error(self):
        self.assertEqual(detect_level("FATAL ERROR db gone"), "FATAL")

    def test_chinese(self):
        self.assertEqual(detect_level("严重：磁盘已满"), "FATAL")
        self.assertEqual(detect_level("警告：连接重试"), "WARN")

    def test_unknown_is_honest(self):
        """认不出来就说认不出来，不许瞎猜成 INFO。"""
        self.assertEqual(detect_level("hello world"), "未知")

    def test_empty(self):
        self.assertEqual(detect_level(""), "未知")


class TestExtractTs(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(extract_ts("[2026-10-11 09:30:00] x"), "2026-10-11 09:30:00")

    def test_slash(self):
        self.assertEqual(extract_ts("2026/10/11 09:30:00 x"), "2026-10-11 09:30:00")

    def test_date_only(self):
        self.assertEqual(extract_ts("2026-10-11 something"), "2026-10-11")

    def test_none_found(self):
        self.assertEqual(extract_ts("no time here"), "")


class TestTriageText(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.log = self.dir / "app.log"
        self.log.write_text(
            "\n".join([
                "2026-10-11 09:00:00 INFO 服务启动",
                "2026-10-11 09:00:05 ERROR timeout after 123ms",
                "2026-10-11 09:00:07 ERROR timeout after 456ms",
                "2026-10-11 09:00:09 WARN 磁盘 80%",
                "2026-10-11 10:00:00 ERROR 连接失败 10.0.0.5",
                "",
            ]), encoding="utf-8")

    def test_counts(self):
        r = triage([self.log])
        self.assertEqual(r["total_files"], 1)
        # 文件内容是 5 行有效日志 + 末尾一个空行；流式读会读出 5 行
        self.assertEqual(r["total_lines"], 5)

    def test_errors_merged_into_two_kinds(self):
        """两条不同数字的 timeout 必须归成 1 类。"""
        r = triage([self.log])
        keys = [k for k, _ in r["kinds"]]
        self.assertEqual(len(r["kinds"]), 2, keys)
        timeout_kinds = [v["count"] for k, v in r["kinds"] if "timeout" in k]
        self.assertEqual(timeout_kinds, [2])

    def test_first_and_last_location(self):
        r = triage([self.log])
        for k, v in r["kinds"]:
            if "timeout" in k:
                self.assertEqual(v["first_ts"], "2026-10-11 09:00:05")
                self.assertEqual(v["last_ts"], "2026-10-11 09:00:07")
                self.assertIn("app.log:2", v["first_at"])

    def test_levels(self):
        r = triage([self.log])
        d = dict(r["levels"])
        self.assertEqual(d.get("ERROR"), 3)
        self.assertEqual(d.get("INFO"), 1)

    def test_empty_file(self):
        empty = self.dir / "empty.log"
        empty.write_text("", encoding="utf-8")
        r = triage([empty])
        self.assertEqual(r["total_lines"], 0)
        self.assertEqual(r["kinds"], [])

    def test_no_timestamp(self):
        """没有时间戳时仍要能归并，只是首次/末次时间给不出。"""
        f = self.dir / "nots.log"
        f.write_text("ERROR upstream failed after 100ms\nERROR upstream failed after 250ms\n",
                     encoding="utf-8")
        r = triage([f])
        self.assertEqual(r["span"], " ~ ")
        self.assertEqual(len(r["kinds"]), 1)
        self.assertEqual(r["kinds"][0][1]["count"], 2)

    def test_binary_safe(self):
        """带乱码字节的文件不能把整个程序打崩。"""
        f = self.dir / "bin.log"
        f.write_bytes(b"2026-10-11 09:00:00 ERROR \xff\xfe bad bytes\n")
        r = triage([f])
        self.assertEqual(r["total_lines"], 1)

    def test_bursts_count_errors_only(self):
        """突增只看错误行：某小时 INFO 刷屏不该被判成突增（2026-10-11 复核补）。"""
        f = self.dir / "burst.log"
        lines = ["2026-10-11 08:00:00 ERROR disk error"]        # 08 时：1 条错误
        lines += ["2026-10-11 09:00:00 INFO 心跳正常"] * 20      # 09 时：INFO 刷屏 + 1 错误
        lines.append("2026-10-11 09:00:01 ERROR timeout after 1ms")
        lines += ["2026-10-11 10:00:00 ERROR timeout after 2ms"] * 10  # 10 时：10 条错误
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = triage([f])
        # 旧版按全部行数算（09 时 21 行最高），会漏掉真正的错误突增；新版只看错误行
        self.assertEqual(r["bursts"], [("2026-10-11 10", 10)])


class TestTriageJson(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def _w(self, name, summary, top_error=None):
        payload = {"summary": summary}
        if top_error is not None:
            payload["error"] = top_error
        (self.dir / name).write_text(json.dumps(payload), encoding="utf-8")

    def test_success_and_error_split(self):
        self._w("a.json", {"timestamp": "2026-10-11T01:00:00Z", "status": 200})
        self._w("b.json", {"timestamp": "2026-10-11T02:00:00Z", "status": 502},
                top_error="upstream connect failed (os error 10061)")
        r = triage(list(self.dir.glob("*.json")))
        lv = dict(r["levels"])
        self.assertEqual(lv.get("INFO"), 1)
        self.assertEqual(lv.get("ERROR"), 1)

    def test_top_level_error_used(self):
        """error 在顶层而不是 summary 里 —— 真实日志踩过这个坑。"""
        self._w("c.json", {"timestamp": "2026-10-11T02:00:00Z", "status": 500},
                top_error="boom")
        r = triage(list(self.dir.glob("*.json")))
        self.assertEqual(len(r["kinds"]), 1)
        self.assertIn("boom", r["kinds"][0][0])

    def test_broken_json_skipped(self):
        (self.dir / "bad.json").write_text("{not json", encoding="utf-8")
        self._w("ok.json", {"timestamp": "2026-10-11T02:00:00Z", "status": 200})
        r = triage(list(self.dir.glob("*.json")))
        self.assertEqual(r["total_files"], 2)

    def test_missing_summary_skipped(self):
        (self.dir / "nosum.json").write_text('{"foo":1}', encoding="utf-8")
        self.assertEqual(triage(list(self.dir.glob("*.json")))["total_lines"], 0)

    def test_json_without_status_is_unknown(self):
        """没有 status 字段：认不出来就说认不出来，不许猜成 ERROR（2026-10-11 复核补）。"""
        self._w("ns.json", {"timestamp": "2026-10-11T03:00:00Z"})
        r = triage(list(self.dir.glob("*.json")))
        lv = dict(r["levels"])
        self.assertEqual(lv.get("未知"), 1)
        self.assertIsNone(lv.get("ERROR"))


if __name__ == "__main__":
    unittest.main(verbosity=2)