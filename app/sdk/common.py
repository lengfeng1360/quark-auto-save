from datetime import datetime, timezone, timedelta


def iso_to_cst(iso_time_str: str) -> str:
    """
    将 ISO 格式的时间字符串转换为 CST (UTC+8) 时间并格式化。
    修复了 'Z' 后缀解析问题和 '0001-01-01' 异常。
    """
    if not iso_time_str:
        return ""

    try:
        # 1. 修复 Python < 3.11 对 'Z' 后缀的不支持问题
        # 将 'Z' 替换为 '+00:00' 以便 fromisoformat 能正确识别为 UTC
        if iso_time_str.endswith("Z"):
            iso_time_str = iso_time_str[:-1] + "+00:00"

        # 2. 解析时间
        dt = datetime.fromisoformat(iso_time_str)

        # 3. 过滤无效的“零值”年份 (如 0001-01-01)
        if dt.year < 1970:
            return ""

        # 4. 确保时间对象是“时区感知”的 (Aware)
        # 如果解析出来没有时区信息，默认为 UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        # 5. 统一转换为 CST (UTC+8)
        cst_tz = timezone(timedelta(hours=8))
        dt_cst = dt.astimezone(cst_tz)

        # 6. 格式化输出
        return dt_cst.strftime("%Y-%m-%d %H:%M:%S")

    except ValueError:
        # 如果格式完全无法解析，返回空字符串或原始字符串，防止程序崩溃
        print(f"Warning: Failed to parse date: {iso_time_str}")
        return ""
    except Exception as e:
        print(f"Error processing date {iso_time_str}: {e}")
        return ""