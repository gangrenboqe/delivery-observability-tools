"""单元测试：只测纯函数，不读真实日志、不联网。

运行：python -m unittest discover -s tests
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_call_report import (build_summary, load_calls, normalize_error,
                             percentile, _parse_ts, _safe)


class TestPercentile(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(percentile([], 95), 0.0)

    def test_single(self):
        self.assertEqual(percentile([500], 95), 500.0)

    def test_median(self):
        self.assertEqual(percentile([1, 2, 3, 4, 5], 50), 3.0)

    def test_p95_near_max(self):
        """95 分位应该贴近最大值 —— 这正是它能抓到长尾的原因。"""
        xs = [10] * 19 + [30000]
        p95 = percentile(xs, 95)
        self.assertGreater(p95, 1000)
        self.assertLessEqual(p95, 30000)

    def test_average_understates_slow_calls(self):
        """对照实验：慢调用占 10% 时，P95 能看出来，而平均值把它大幅拉低。"""
        xs = [100] * 90 + [30000] * 10
        avg = sum(xs) / len(xs)
        p95 = percentile(xs, 95)
        self.assertLess(avg, p95, "平均值必须明显低于 P95，否则等于没测出长尾")

    def test_single_outlier_hides_from_p95(self):
        """
        反向诚实测试：**只有个别几次卡住时，P95 是看不出来的**。
        这条测试的作用是不让我把 P95 吹成万能指标 —— 真正的硬指标是最长耗时。
        """
        xs = [100] * 99 + [30000]
        self.assertEqual(percentile(xs, 95), 100.0)
        self.assertEqual(max(xs), 30000)

    def test_unsorted_input(self):
        self.assertEqual(percentile([5, 1, 3], 50), 3.0)


class TestNormalizeError(unittest.TestCase):
    def test_none(self):
        self.assertEqual(normalize_error(None), "（无错误信息）")

    def test_numbers_collapsed(self):
        """同类错误里的数字必须被抹掉，否则 Top N 全是重复行。"""
        a = normalize_error("timeout after 123ms")
        b = normalize_error("timeout after 456ms")
        self.assertEqual(a, b)
        self.assertIn("N", a)

    def test_hex_id_masked(self):
        a = normalize_error("conn 8b1a01b6-1267-4880 failed")
        b = normalize_error("conn 9f2b02c7-1267-4880 failed")
        self.assertEqual(a, b)

    def test_windows_path_masked(self):
        got = normalize_error(r"cannot open C:\Users\Someone\secret\file.txt")
        self.assertNotIn("Someone", got)

    def test_length_capped(self):
        self.assertLessEqual(len(normalize_error("x" * 500)), 80)

    def test_empty_string(self):
        self.assertEqual(normalize_error(""), "（无错误信息）")


class TestSafeFields(unittest.TestCase):
    def test_drops_request_body(self):
        """隐私断言：请求正文绝不能进我们的数据结构。"""
        summary = {
            "timestamp": "2026-10-06T02:57:03.211Z", "status": 200,
            "model": "m", "duration": 100, "tokens": {"in": 3, "out": 5},
            "requestBody": {"messages": [{"role": "user", "content": "我的秘密"}]},
            "responseBody": {"choices": [{"text": "我的秘密"}]},
        }
        out = _safe(summary)
        self.assertNotIn("requestBody", out)
        self.assertNotIn("responseBody", out)
        self.assertNotIn("我的秘密", json.dumps(out, ensure_ascii=False))
        self.assertEqual(out["tokens_in"], 3)
        self.assertEqual(out["tokens_out"], 5)

    def test_timestamp_parse(self):
        self.assertEqual(_parse_ts("2026-10-06T02:57:03.211Z"), "2026-10-06 10:57:03")

    def test_timestamp_bad_input_kept(self):
        self.assertEqual(_parse_ts("not-a-time"), "not-a-time")


class TestLoadAndSummary(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = Path(tempfile.mkdtemp())

    def _write(self, name, summary):
        (self.dir / name).write_text(json.dumps({"summary": summary}), encoding="utf-8")

    def test_missing_dir_returns_empty(self):
        self.assertEqual(load_calls(self.dir / "nope"), [])

    def test_bad_file_does_not_break_all(self):
        """一个坏文件不能让整份报表失败。"""
        (self.dir / "good.json").write_text(json.dumps(
            {"summary": {"timestamp": "2026-10-06T00:00:00Z", "status": 200, "duration": 10}}),
            encoding="utf-8")
        (self.dir / "broken.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(len(load_calls(self.dir)), 1)

    def test_summary_math(self):
        self._write("a.json", {"timestamp": "2026-10-06T00:00:00Z", "status": 200,
                               "model": "m", "duration": 100, "tokens": {"in": 10, "out": 2}})
        self._write("b.json", {"timestamp": "2026-10-06T01:00:00Z", "status": 500,
                               "model": "m", "duration": 900, "tokens": {"in": 1, "out": 0},
                               "error": "boom"})
        s = build_summary(load_calls(self.dir))
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["success"], 1)
        self.assertEqual(s["failed"], 1)
        self.assertEqual(s["success_rate"], 50.0)
        self.assertEqual(s["tokens"]["in"], 11)
        self.assertEqual(s["tokens"]["out"], 2)
        self.assertEqual(s["duration_ms"]["max"], 900)
        self.assertEqual(s["duration_ms"]["p50"], 500.0)

    def test_errors_grouped(self):
        for i in range(3):
            self._write(f"e{i}.json", {"timestamp": "2026-10-06T00:00:0%dZ" % i,
                                       "status": 502, "duration": 10,
                                       "error": "upstream connect failed (os error 1006%d)" % i})
        s = build_summary(load_calls(self.dir))
        self.assertEqual(len(s["errors"]), 1, "三条同因错误应归成一条")
        self.assertEqual(s["errors"][0][1], 3)

    def test_status_2xx_counts_as_success(self):
        self._write("x.json", {"timestamp": "2026-10-06T00:00:00Z", "status": 204, "duration": 1})
        self.assertEqual(build_summary(load_calls(self.dir))["success"], 1)

    def test_empty_calls_does_not_crash(self):
        s = build_summary([])
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["success_rate"], 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)