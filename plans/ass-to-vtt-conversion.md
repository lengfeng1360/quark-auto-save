# ASS 字幕转换为 VTT 格式实现计划

## 目标
实现 ASS/SSA 格式字幕到 VTT 格式的转换，使 ArtPlayer 能够正确显示 ASS 字幕的基础内容。

## 背景分析

### 当前代码状态
在 `app/templates/new/library.html` 中：
- 第 915 行：已识别 ASS 格式字幕扩展名
- 第 1039-1042 行：ASS 格式当前以 `text/plain` 直接传递给播放器，样式丢失

### ASS 格式特点
```
[Script Info]
Title: Example
...

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, ...
...

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
Dialogue: 0,0:00:01.00,0:00:04.00,Default,,0,0,0,,Hello {\b1}World{\b0}
```

时间格式：`H:MM:SS.CC`（时:分:秒.厘秒）

## 实施方案

### 1. 实现 assToVtt 转换函数

**位置**：在 `srtToVtt` 函数后（约第 1173 行之后）

**函数签名**：
```javascript
function assToVtt(assContent)
```

**处理流程**：
1. 添加 VTT 头部：`WEBVTT\n\n`
2. 移除 BOM 头（如果有）
3. 解析 ASS 文件，定位 `[Events]` 节
4. 提取 `Dialogue` 行
5. 解析每行的字段：
   - 格式：`Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text`
   - 提取 Start, End, Text 字段
6. 时间格式转换：
   - ASS: `H:MM:SS.CC` 或 `H:MM:SS.cc`（小数点位数可变）
   - VTT: `HH:MM:SS.mmm`（补零到3位）
7. 处理文本样式标签：
   - `\n` → `\n`（保留换行）
   - `\N` → `\n`
   - `\h` → ` `（硬空格）
   - 移除样式标签 `{\...}`（可选：转换部分为 HTML）
8. 生成 VTT 格式输出

**样式标签处理策略**（简化版）：
- 移除所有 `{\...}` 标签
- 保留 `\n` 和 `\N` 作为换行符
- 保留纯文本内容

**示例转换**：
```
输入: Dialogue: 0,0:00:01.00,0:00:04.00,Default,,0,0,0,,Hello {\b1}World{\b0}
输出: 00:00:01.000 --> 00:00:04.000
     Hello World
```

### 2. 修改 loadSubtitleWithBlob 函数

**位置**：第 1039-1042 行

**修改内容**：
```javascript
// 修改前：
} else if (format === 'ass' || format === 'ssa') {
    // ASS/SSA 格式：直接使用，ArtPlayer 原生支持
    blobContent = decodedContent;
    mimeType = 'text/plain';
}

// 修改后：
} else if (format === 'ass' || format === 'ssa') {
    // ASS/SSA 格式：转换为 VTT
    blobContent = assToVtt(decodedContent);
    mimeType = 'text/vtt';
}
```

### 3. 代码实现细节

#### 时间格式转换逻辑
```javascript
function convertAssTimeToVtt(assTime) {
    // ASS 时间: H:MM:SS.CC 或 HH:MM:SS.CC
    // VTT 时间: HH:MM:SS.mmm
    const parts = assTime.split(':');
    if (parts.length === 3) {
        const hours = parts[0].padStart(2, '0');
        const minutes = parts[1];
        const secondsWithCenti = parts[2];
        const secondsParts = secondsWithCenti.split('.');
        const seconds = secondsParts[0];
        const centiseconds = secondsParts[1] || '00';
        const milliseconds = (parseInt(centiseconds) * 10).toString().padStart(3, '0');
        return `${hours}:${minutes}:${seconds}.${milliseconds}`;
    }
    return assTime; // 回退
}
```

#### 样式标签清理逻辑
```javascript
function cleanAssStyles(text) {
    // 替换换行符
    let cleaned = text.replace(/\\n/gi, '\n');
    cleaned = cleaned.replace(/\\N/g, '\n');
    cleaned = cleaned.replace(/\\h/g, ' ');

    // 移除样式标签 {\\...}
    cleaned = cleaned.replace(/\{\\[^}]+\}/g, '');

    return cleaned.trim();
}
```

## 实施步骤

1. **添加 assToVtt 函数**
   - 在 `srtToVtt` 函数之后添加
   - 实现完整的解析和转换逻辑

2. **修改 loadSubtitleWithBlob 函数**
   - 更新 ASS/SSA 格式处理分支
   - 调用 assToVtt 进行转换
   - 设置正确的 MIME 类型

3. **测试验证**
   - 使用包含各种 ASS 特性的字幕文件测试
   - 验证时间轴正确性
   - 验证文本内容正确性

## 注意事项

1. **编码处理**：ASS 文件内容已通过 `detectAndDecodeSubtitle` 解码，assToVtt 接收的是解码后的字符串

2. **时间格式差异**：
   - ASS 厘秒精度（CC）= 1/100 秒
   - VTT 毫秒精度 = 1/1000 秒
   - 需要进行乘法转换：centiseconds * 10 = milliseconds

3. **样式支持**：此方案为简化转换，会丢失 ASS 的高级样式（颜色、字体、特效等）

4. **兼容性**：确保与现有的 `srtToVtt` 函数风格一致

## 后续优化方向

1. 保留部分基本样式（粗体、斜体、颜色）转换为 HTML
2. 支持注释行（Comment:）的处理
3. 支持多语言 ASS 文件检测