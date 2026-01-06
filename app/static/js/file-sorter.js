/**
 * FileSorter - 文件排序类
 * 提供多种排序方式：基于名称、基于结构相似度、基于剧集编号
 */
class FileSorter {
    /**
     * 构造函数
     * @param {string} sortType - 排序类型: 'name' | 'structure' | 'episode'
     */
    constructor(sortType = 'name') {
        this.sortType = sortType;
        this.commonSubstrings = [];
        this.videoExtensions = ['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v', 'ts', 'rmvb', '3gp', 'mpg', 'mpeg', 'm3u8'];
    }

    /**
     * 设置排序类型
     * @param {string} sortType
     */
    setSortType(sortType) {
        this.sortType = sortType;
    }

    /**
     * 主排序入口
     * @param {Array} fileList - 文件列表 [{name, is_dir, size}, ...]
     * @returns {Array} 排序后的文件列表
     */
    sort(fileList) {
        if (!fileList || fileList.length === 0) {
            return fileList;
        }

        // 计算当前目录视频文件的公共子串
        const videoFiles = fileList.filter(f => !f.is_dir && this.isVideoFile(f.name));
        const videoNames = videoFiles.map(f => f.name);
        this.commonSubstrings = this.findCommonSubstrings(videoNames);

        switch (this.sortType) {
            case 'structure':
                return this.sortByStructure(fileList);
            case 'episode':
                return this.sortByEpisode(fileList);
            case 'name':
            default:
                return this.sortByName(fileList);
        }
    }

    /**
     * 基于差异部分的自然排序（原有功能）
     */
    sortByName(fileList) {
        return fileList.sort((a, b) => {
            // 文件夹优先
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            
            // 如果都是文件
            if (!a.is_dir && !b.is_dir) {
                // 如果都是视频文件，使用基于差异部分的排序
                if (this.isVideoFile(a.name) && this.isVideoFile(b.name)) {
                    return this.uniquePartNaturalCompare(a.name, b.name, this.commonSubstrings);
                }
                
                // 其他文件使用自然排序
                return this.naturalCompare(a.name, b.name);
            }
            
            // 如果都是文件夹，使用自然排序
            return this.naturalCompare(a.name, b.name);
        });
    }

    /**
     * 基于结构相似度的分组排序（新功能 - 从 Python 转换）
     */
    sortByStructure(fileList) {
        // 获取视频文件名
        const videoFiles = fileList.filter(f => !f.is_dir && this.isVideoFile(f.name));
        const videoNames = videoFiles.map(f => f.name);
        
        if (videoNames.length === 0) {
            return this.sortByName(fileList);
        }

        // 按结构相似度分组
        const groups = this.classifyByStructuralSimilarity(videoNames);
        
        // 创建文件名到分组信息的映射
        const fileGroupMap = new Map();
        groups.forEach(group => {
            group.members.forEach(member => {
                fileGroupMap.set(member, group);
            });
        });
        this.structureGroups = groups; // 保存分组信息用于高亮
        this.fileGroupMap = fileGroupMap;

        // 排序逻辑：
        // 1. 文件夹优先
        // 2. 视频文件按分组排序（组内按集号排序）
        // 3. 其他文件按名称排序
        return fileList.sort((a, b) => {
            // 文件夹优先
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            
            // 如果都是文件夹
            if (a.is_dir && b.is_dir) {
                return this.naturalCompare(a.name, b.name);
            }
            
            // 如果都是视频文件
            if (this.isVideoFile(a.name) && this.isVideoFile(b.name)) {
                const groupA = fileGroupMap.get(a.name);
                const groupB = fileGroupMap.get(b.name);
                
                // 如果不在同一分组，按分组数量降序排列
                if (groupA !== groupB) {
                    return (groupB?.count || 0) - (groupA?.count || 0);
                }
                
                // 同一分组内，按集号排序
                const episodeA = this.extractEpisodeNumber(a.name, groupA);
                const episodeB = this.extractEpisodeNumber(b.name, groupB);
                
                if (episodeA !== null && episodeB !== null) {
                    const seasonDiff = (groupA?.season_template || 1) - (groupB?.season_template || 1);
                    if (seasonDiff !== 0) return seasonDiff;
                    return episodeA - episodeB;
                }
                
                // 无法提取集号时，按名称排序
                return this.naturalCompare(a.name, b.name);
            }
            
            // 如果有一个不是视频文件
            if (this.isVideoFile(a.name)) return -1;
            if (this.isVideoFile(b.name)) return 1;
            
            // 其他文件按名称排序
            return this.naturalCompare(a.name, b.name);
        });
    }

    /**
     * 基于剧集编号的排序（组合功能）
     */
    sortByEpisode(fileList) {
        return fileList.sort((a, b) => {
            // 文件夹优先
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            
            // 如果都是文件
            if (!a.is_dir && !b.is_dir) {
                // 如果都是视频文件，尝试按集号排序
                if (this.isVideoFile(a.name) && this.isVideoFile(b.name)) {
                    const epA = this.extractEpisodeNumberSimple(a.name);
                    const epB = this.extractEpisodeNumberSimple(b.name);
                    
                    if (epA !== null && epB !== null) {
                        return epA - epB;
                    }
                    
                    // 无法提取集号时，使用基于差异部分的排序
                    return this.uniquePartNaturalCompare(a.name, b.name, this.commonSubstrings);
                }
                
                // 其他文件使用自然排序
                return this.naturalCompare(a.name, b.name);
            }
            
            // 如果都是文件夹，使用自然排序
            return this.naturalCompare(a.name, b.name);
        });
    }

    // ==================== 辅助方法 ====================

    /**
     * 判断是否为视频文件
     */
    isVideoFile(fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        return this.videoExtensions.includes(ext);
    }

    /**
     * 简单的自然排序函数
     */
    naturalCompare(a, b) {
        const regex = /(\d+)|(\D+)/g;
        const aParts = a.match(regex) || [];
        const bParts = b.match(regex) || [];
        
        const minLength = Math.min(aParts.length, bParts.length);
        
        for (let i = 0; i < minLength; i++) {
            const aPart = aParts[i];
            const bPart = bParts[i];
            
            // 如果都是数字部分
            if (/^\d+$/.test(aPart) && /^\d+$/.test(bPart)) {
                const aNum = parseInt(aPart, 10);
                const bNum = parseInt(bPart, 10);
                if (aNum !== bNum) {
                    return aNum - bNum;
                }
            } else {
                const comparison = aPart.localeCompare(bPart);
                if (comparison !== 0) {
                    return comparison;
                }
            }
        }
        
        return aParts.length - bParts.length;
    }

    /**
     * 基于差异部分的自然排序函数
     */
    uniquePartNaturalCompare(a, b, commonSubstrings) {
        const uniqueA = this.extractUniquePart(a, commonSubstrings);
        const uniqueB = this.extractUniquePart(b, commonSubstrings);
        
        if (uniqueA === uniqueB) {
            return a.localeCompare(b);
        }
        
        return this.naturalCompare(uniqueA, uniqueB);
    }

    /**
     * 从文件名中提取差异部分（非公共部分）
     */
    extractUniquePart(fileName, commonSubstrings) {
        if (!commonSubstrings || commonSubstrings.length === 0) {
            return fileName;
        }
        
        const isCommon = new Array(fileName.length).fill(false);
        const sortedCommons = [...commonSubstrings].sort((a, b) => b.length - a.length);
        
        for (const sub of sortedCommons) {
            let startPos = 0;
            while (true) {
                const index = fileName.indexOf(sub, startPos);
                if (index === -1) break;
                
                for (let k = 0; k < sub.length; k++) {
                    isCommon[index + k] = true;
                }
                startPos = index + 1;
            }
        }
        
        let uniquePart = '';
        for (let i = 0; i < fileName.length; i++) {
            if (!isCommon[i]) {
                uniquePart += fileName[i];
            }
        }
        
        return uniquePart || fileName;
    }

    /**
     * 查找公共子串
     */
    findCommonSubstrings(strList) {
        if (!strList || strList.length === 0) return [];

        const lowerStrList = strList.map(s => s.toLowerCase());
        const shortestLower = lowerStrList.reduce((a, b) => a.length <= b.length ? a : b);
        const n = shortestLower.length;

        const commonLowerCandidates = new Set();

        for (let length = 1; length <= n; length++) {
            for (let i = 0; i <= n - length; i++) {
                const subLower = shortestLower.substring(i, i + length);
                if (lowerStrList.every(ls => ls.includes(subLower))) {
                    commonLowerCandidates.add(subLower);
                }
            }
        }

        if (commonLowerCandidates.size === 0) return [];

        const sortedLower = Array.from(commonLowerCandidates).sort((a, b) => b.length - a.length);
        const maximalLower = [];
        for (const cand of sortedLower) {
            if (!maximalLower.some(existing => existing.includes(cand))) {
                maximalLower.push(cand);
            }
        }

        const finalResult = [];
        const firstStrLower = lowerStrList[0];
        maximalLower.sort((a, b) => firstStrLower.indexOf(a) - firstStrLower.indexOf(b));

        for (const subLower of maximalLower) {
            const variants = new Set();
            
            strList.forEach((originalStr) => {
                const lowerOrig = originalStr.toLowerCase();
                let startPos = 0;
                while ((startPos = lowerOrig.indexOf(subLower, startPos)) !== -1) {
                    const originalPiece = originalStr.substring(startPos, startPos + subLower.length);
                    variants.add(originalPiece);
                    startPos += subLower.length;
                    break;
                }
            });

            variants.forEach(v => finalResult.push(v));
        }

        return finalResult;
    }

    /**
     * 高亮文件名 - 根据当前排序方式决定高亮策略
     * @param {string} fileName - 文件名
     * @returns {Object} - { html, title }
     */
    highlightFileName(fileName) {
        switch (this.sortType) {
            case 'structure':
            case 'episode':
                return this.highlightEpisodeNumber(fileName);
            case 'name':
            default:
                return this.highlightCommonPart(fileName, this.commonSubstrings);
        }
    }

    /**
     * 高亮文件名中的公共部分（按名称排序时使用）
     */
    highlightCommonPart(fileName, commonSubstrings) {
        if (!commonSubstrings || commonSubstrings.length === 0) {
            return fileName;
        }

        const isCommon = new Array(fileName.length).fill(false);
        const sortedCommons = [...commonSubstrings].sort((a, b) => b.length - a.length);

        for (const sub of sortedCommons) {
            let startPos = 0;
            while (true) {
                const index = fileName.indexOf(sub, startPos);
                if (index === -1) break;

                for (let k = 0; k < sub.length; k++) {
                    isCommon[index + k] = true;
                }
                startPos = index + 1;
            }
        }

        let html = '';
        let currentType = null;
        let buffer = '';

        for (let i = 0; i < fileName.length; i++) {
            const type = isCommon[i] ? 'common' : 'unique';

            if (type !== currentType) {
                if (buffer) {
                    if (currentType === 'common') {
                        html += `<span class="common-part">${buffer}</span>`;
                    } else {
                        html += `<span class="unique-part">${buffer}</span>`;
                    }
                }
                buffer = fileName[i];
                currentType = type;
            } else {
                buffer += fileName[i];
            }
        }

        if (buffer) {
            if (currentType === 'common') {
                html += `<span class="common-part">${buffer}</span>`;
            } else {
                html += `<span class="unique-part">${buffer}</span>`;
            }
        }

        return {
            html: html,
            title: fileName
        };
    }

    /**
     * 高亮文件名中的集号部分（按集号/结构排序时使用）
     */
    highlightEpisodeNumber(fileName) {
        // 尝试多种模式匹配集号
        let episodeMatch = null;
        let matchType = '';
        
        //1. 标准SxxExy模式
        const seMatch = fileName.match(/(S\d+[^a-zA-Z]*E\d+)/i);
        if (seMatch) {
            episodeMatch = { start: seMatch.index, end: seMatch.index + seMatch[0].length, full: seMatch[0] };
            matchType = 'se';
        }
        
        // 2. 孤立的E标记
        if (!episodeMatch) {
            const eMatch = fileName.match(/(E\d+)/i);
            if (eMatch) {
                episodeMatch = { start: eMatch.index, end: eMatch.index + eMatch[0].length, full: eMatch[0] };
                matchType = 'e';
            }
        }
        
        // 3. 中文"第X集"模式
        if (!episodeMatch) {
            const cnMatch = fileName.match(/([^\d]*(\d+|[一二三四五六七八九十零]+)[^\d-]*集)/);
            if (cnMatch) {
                episodeMatch = { start: cnMatch.index, end: cnMatch.index + cnMatch[0].length, full: cnMatch[0] };
                matchType = 'cn';
            }
        }
        
        // 4. E前缀数字
        if (!episodeMatch) {
            const ePrefixMatch = fileName.match(/^(E\d+)/i);
            if (ePrefixMatch) {
                episodeMatch = { start: 0, end: ePrefixMatch[0].length, full: ePrefixMatch[0] };
                matchType = 'eprefix';
            }
        }
        
        // 5. 提取第一个数字（作为集号）
        if (!episodeMatch) {
            const numMatch = fileName.match(/(\d+)/);
            if (numMatch) {
                episodeMatch = { start: numMatch.index, end: numMatch.index + numMatch[0].length, full: numMatch[0] };
                matchType = 'num';
            }
        }

        if (!episodeMatch) {
            return fileName;
        }

        // 构建高亮 HTML
        let html = '';
        let pos = 0;
        
        while (pos < fileName.length) {
            if (pos === episodeMatch.start) {
                // 高亮集号部分
                if (matchType === 'se') {
                    // SxxExy 模式，只高亮 E后面的数字
                    const ePos = fileName.substring(pos).search(/E/i);
                    if (ePos !== -1) {
                        html += `<span class="common-part">${fileName.substring(pos, pos + ePos + 1)}</span>`;
                        html += `<span class="unique-part">${fileName.substring(pos + ePos + 1, episodeMatch.end)}</span>`;
                    } else {
                        html += `<span class="unique-part">${fileName.substring(pos, episodeMatch.end)}</span>`;
                    }
                } else {
                    html += `<span class="unique-part">${fileName.substring(pos, episodeMatch.end)}</span>`;
                }
                pos = episodeMatch.end;
            } else {
                html += fileName[pos];
                pos++;
            }
        }

        return {
            html: html,
            title: fileName
        };
    }

    // ==================== 结构相似度分析（Python 转换）====================

    /**
     * 归一化签名 - 将连续数字替换为占位符
     */
    normalizeSignature(name) {
        return name.replace(/\d+/g, 'NUM');
    }

    /**
     * 中文数字映射表
     */
    static CN_NUM_MAP = {
        '零': 0, '一': 1, '二': 2, '三': 3, '四': 4, '五': 5,
        '六': 6, '七': 7, '八': 8, '九': 9, '十': 10
    };

    /**
     * 将中文数字转换为整数
     */
    chineseToNumber(cnStr) {
        cnStr = cnStr.trim();
        const map = FileSorter.CN_NUM_MAP;
        
        if (cnStr.includes('十')) {
            const parts = cnStr.split('十');
            let num = 0;
            
            if (parts[0]) {
                num += (map[parts[0]] || 0) * 10;
            } else if (parts[0] === '') {
                num = 10;
            }
            
            if (parts[1]) {
                num += map[parts[1]] || 0;
            }
            
            return num;
        } else {
            return map[cnStr] || 0;
        }
    }

    /**
     * 从文件名中提取集号（基于分组信息）
     */
    extractEpisodeNumber(fileName, groupInfo) {
        if (!groupInfo) return null;

        // 策略1: 标准SxxExy模式
        const sMatch = fileName.match(/S(\d+)/i);
        const eMatch = fileName.match(/E(\d+)/i);
        if (sMatch && eMatch) {
            return parseInt(eMatch[1], 10);
        }

        // 策略2: 粘连的SxxExy模式
        const粘连Match = fileName.match(/S(\d+)[^a-zA-Z]*E(\d+)/i);
        if (粘连Match) {
            return parseInt(粘连Match[2], 10);
        }

        // 策略3: 孤立的E标记
        const eOnlyMatch = fileName.match(/E(\d+)/i);
        if (eOnlyMatch) {
            return parseInt(eOnlyMatch[1], 10);
        }

        // 策略4: 中文"第X集"模式
        const cnMatch = fileName.match(/[^\d]*(\d+|[一二三四五六七八九十零]+)[^\d-]*集/);
        if (cnMatch) {
            const epStr = cnMatch[1];
            if (/^\d+$/.test(epStr)) {
                return parseInt(epStr, 10);
            } else {
                return this.chineseToNumber(epStr);
            }
        }

        // 策略5: E前缀数字
        const ePrefixMatch = fileName.match(/^E(\d+)/i);
        if (ePrefixMatch) {
            return parseInt(ePrefixMatch[1], 10);
        }

        // 策略6: 纯数字（从差异部分提取）
        const uniquePart = this.extractUniquePart(fileName, this.commonSubstrings);
        const numMatch = uniquePart.match(/\d+/);
        if (numMatch) {
            return parseInt(numMatch[0], 10);
        }

        return null;
    }

    /**
     * 简单提取集号（不依赖分组信息）
     */
    extractEpisodeNumberSimple(fileName) {
        // SxxExy 模式
        const sEMatch = fileName.match(/S\d+[^a-zA-Z]*E(\d+)/i);
        if (sEMatch) return parseInt(sEMatch[1], 10);

        // E标记
        const eMatch = fileName.match(/E(\d+)/i);
        if (eMatch) return parseInt(eMatch[1], 10);

        // 中文集号
        const cnMatch = fileName.match(/[^\d]*(\d+|[一二三四五六七八九十零]+)[^\d-]*集/);
        if (cnMatch) {
            const epStr = cnMatch[1];
            if (/^\d+$/.test(epStr)) {
                return parseInt(epStr, 10);
            } else {
                return this.chineseToNumber(epStr);
            }
        }

        // E前缀
        const ePrefixMatch = fileName.match(/^E(\d+)/i);
        if (ePrefixMatch) return parseInt(ePrefixMatch[1], 10);

        // 提取第一个数字
        const numMatch = fileName.match(/\d+/);
        if (numMatch) return parseInt(numMatch[0], 10);

        return null;
    }

    /**
     * 提取结构信息（从分组）
     */
    extractStructureFromGroup(filesInGroup) {
        if (!filesInGroup || filesInGroup.length === 0) {
            return {
                structure: '未能识别或非剧集文件',
                season_template: null,
                episode_template: null,
                source_example: null
            };
        }

        const firstFile = filesInGroup[0];

        // 策略1: 标准SxxExy模式
        const sEMatch = firstFile.match(/S(\d+)[^a-zA-Z]*E(\d+)/i);
        if (sEMatch) {
            return {
                structure: '包含SxxExy模式',
                season_template: parseInt(sEMatch[1], 10),
                episode_template: parseInt(sEMatch[2], 10),
                source_example: firstFile
            };
        }

        // 策略2: 增强的粘连检测
        const hasS = filesInGroup.some(f => /S\d+/i.test(f));
        const hasE = filesInGroup.some(f => /E\d+/i.test(f));
        if (hasS && hasE) {
            for (const f of filesInGroup) {
                const sMatch = f.match(/S(\d+)/i);
                if (sMatch) {
                    const remaining = f.substring(sMatch.index + sMatch[0].length);
                    const eMatch = remaining.match(/E(\d+)(?!\d)/i);
                    if (eMatch) {
                        return {
                            structure: '包含粘连的SxxExy模式',
                            season_template: parseInt(sMatch[1], 10),
                            episode_template: parseInt(eMatch[1], 10),
                            source_example: f
                        };
                    }
                }
            }
        }

        // 策略3: 孤立的E标记
        for (const f of filesInGroup) {
            const epMatch = f.match(/E(\d+)/i);
            if (epMatch) {
                const sMatch = f.match(/S(\d+)/i);
                const season = sMatch ? parseInt(sMatch[1], 10) : 1;
                return {
                    structure: '包含独立的E标记',
                    season_template: season,
                    episode_template: parseInt(epMatch[1], 10),
                    source_example: f
                };
            }
        }

        // 策略4: 中文"第X集"模式
        const cnMatch = firstFile.match(/(.*?)[^\d]*(\d+|[一二三四五六七八九十零]+)[^\d-]*集/);
        if (cnMatch) {
            const epStr = cnMatch[2];
            let episodeNum;
            if (/^\d+$/.test(epStr)) {
                episodeNum = parseInt(epStr, 10);
            } else {
                episodeNum = this.chineseToNumber(epStr);
            }
            if (episodeNum > 0) {
                return {
                    structure: '中文"第X集"模式',
                    season_template: 1,
                    episode_template: episodeNum,
                    source_example: firstFile
                };
            }
        }

        // 策略5: 纯数字或E前缀
        if (/^\d+$/.test(firstFile)) {
            return {
                structure: '纯数字集号',
                season_template: 1,
                episode_template: parseInt(firstFile, 10),
                source_example: firstFile
            };
        }
        if (filesInGroup.every(f => /^E\d+$/i.test(f))) {
            return {
                structure: 'E前缀数字集号',
                season_template: 1,
                episode_template: parseInt(firstFile.substring(1), 10),
                source_example: firstFile
            };
        }

        return {
            structure: '未能识别或非剧集文件',
            season_template: null,
            episode_template: null,
            source_example: firstFile
        };
    }

    /**
     * 按结构相似度对文件名进行分类
     */
    classifyByStructuralSimilarity(filenames) {
        const groups = new Map();
        
        for (const filename of filenames) {
            // 去除扩展名
            const nameWithoutExt = filename.replace(/\.[^/.]+$/, '').replace(/'/g, "'");
            const signature = this.normalizeSignature(nameWithoutExt);
            
            if (!groups.has(signature)) {
                groups.set(signature, []);
            }
            groups.get(signature).push(nameWithoutExt);
        }

        const report = [];
        for (const [signature, filesInGroup] of groups) {
            const groupData = {
                group_signature: signature,
                count: filesInGroup.length,
                members: filesInGroup
            };
            
            const structureAnalysis = this.extractStructureFromGroup(filesInGroup);
            Object.assign(groupData, structureAnalysis);
            
            report.push(groupData);
        }

        report.sort((a, b) => b.count - a.count);
        return report;
    }
}

// 导出到全局作用域
if (typeof window !== 'undefined') {
    window.FileSorter = FileSorter;
}
