// configmanager.js

const CONFIG_KEY = 'publicAppConfig';

/**
 * 从 localStorage 获取公共配置
 * @returns {object|null} 返回配置对象，如果不存在则返回 null
 */
export const getStoredConfig = () => {
    try {
        const configString = localStorage.getItem(CONFIG_KEY);
        return configString ? JSON.parse(configString) : null;
    } catch (error) {
        console.error("从 localStorage 读取配置失败:", error);
        return null;
    }
};

/**
 * 加载公共配置并存储到 localStorage
 * @param {function(object):void} [callback] - 可选的回调函数，在数据加载成功后执行，接收配置对象作为参数
 * @returns {Promise<object>} 返回一个 Promise，解析为配置对象
 */
export const loadAndStoreConfig = (callback) => {
    return axios.get('/api/public_config')
        .then(response => {
            if (response.data.success) {
                const configData = response.data.data;
                
                // 1. 将数据存入 localStorage
                localStorage.setItem(CONFIG_KEY, JSON.stringify(configData));
                console.log("配置已成功加载并存储到 localStorage");
                
                // 2. 如果提供了回调函数，则调用它，并将数据作为参数传递
                if (typeof callback === 'function') {
                    callback(configData);
                }

                return configData;
            } else {
                throw new Error("API 返回失败");
            }
        })
        .catch(error => {
            console.error("加载配置失败:", error);
            return null;
        });
};

/**
 * 初始化配置：优先从本地读取，如果没有则从服务器加载
 * @param {function(object):void} [callback] - 可选的回调函数，在数据加载成功后执行
 * @returns {Promise<object>}
 */
export const initializeConfig = (callback) => {
    let config = getStoredConfig();
    if (config) {
        console.log("从本地缓存加载配置成功");
        // 即使从缓存加载，也要执行回调以更新UI
        if (typeof callback === 'function') {
            callback(config);
        }
        return Promise.resolve(config);
    } else {
        console.log("本地无缓存，开始从服务器加载配置...");
        return loadAndStoreConfig(callback); // 将回调传递下去
    }
};