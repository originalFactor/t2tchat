document.addEventListener('DOMContentLoaded', () => {
    const loginView = document.getElementById('login-view');
    const chatView = document.getElementById('chat-view');

    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const serverAddrInput = document.getElementById('server_addr');
    const loginBtn = document.getElementById('login-btn');
    const loginError = document.getElementById('login-error');

    const currentUserSpan = document.getElementById('current-user');
    const logoutBtn = document.getElementById('logout-btn');

    const pairGidInput = document.getElementById('pair-gid');
    const pairCidInput = document.getElementById('pair-cid');
    const pairBtn = document.getElementById('pair-btn');
    const pairStatus = document.getElementById('pair-status');

    const availableGroupsList = document.getElementById('available-groups-list');
    const clientsList = document.getElementById('clients-list');
    const allGroupsList = document.getElementById('all-groups-list');
    const availableGroupsCount = document.getElementById('available-groups-count');
    const clientsCount = document.getElementById('clients-count');
    const allGroupsCount = document.getElementById('all-groups-count');

    const currentGroupIdSpan = document.getElementById('current-group-id');
    const messagesDiv = document.getElementById('messages');
    const msgInput = document.getElementById('msg-input');
    const sendBtn = document.getElementById('send-btn');
    const sendStatus = document.getElementById('send-status');

    let currentUsername = '';
    let selectedGid = null;
    let messagePollingInterval = null;
    let listUpdateInterval = null;

    // API Helper
    async function apiCall(endpoint, method = 'GET', body = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        if (body) {
            options.body = JSON.stringify(body);
        }
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ detail: `HTTP error! status: ${response.status}` }));
                throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`API call to ${endpoint} failed:`, error);
            throw error;
        }
    }

    // Login
    loginBtn.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        const server_addr = serverAddrInput.value.trim();

        if (!username || !password || !server_addr) {
            loginError.textContent = '所有字段均为必填项。';
            return;
        }
        loginError.textContent = '';

        try {
            const data = await apiCall('/login', 'POST', { username, password, server_addr });
            if (data.status) {
                currentUsername = username;
                currentUserSpan.textContent = username;
                loginView.style.display = 'none';
                chatView.style.display = 'flex';
                startPolling();
            } else {
                loginError.textContent = `登录失败: ${data.message}`;
            }
        } catch (error) {
            loginError.textContent = `登录错误: ${error.message}`;
        }
    });

    // Logout
    logoutBtn.addEventListener('click', async () => {
        try {
            const data = await apiCall('/logout', 'GET');
            if (data.status) {
                stopPolling();
                chatView.style.display = 'none';
                loginView.style.display = 'flex';
                currentUsername = '';
                selectedGid = null;
                messagesDiv.innerHTML = '';
                availableGroupsList.innerHTML = '';
                clientsList.innerHTML = '';
                allGroupsList.innerHTML = '';
                currentGroupIdSpan.textContent = '未选择';
                loginError.textContent = '已成功登出。';
            } else {
                alert(`登出失败: ${data.message}`);
            }
        } catch (error) {
            alert(`登出错误: ${error.message}`);
        }
    });

    // Send Message
    sendBtn.addEventListener('click', async () => {
        const msg = msgInput.value.trim();
        if (!msg) {
            sendStatus.textContent = '消息不能为空。';
            return;
        }
        if (!selectedGid) {
            sendStatus.textContent = '请先选择一个群组。';
            return;
        }
        sendStatus.textContent = '';

        try {
            const data = await apiCall('/send', 'POST', { gid: selectedGid, msg });
            if (data.status) {
                msgInput.value = '';
                sendStatus.textContent = '发送成功!';
                setTimeout(() => sendStatus.textContent = '', 2000);
                // Optimistically add sent message
                appendMessage({ sender: currentUsername, content: msg, timestamp: new Date().toISOString() }, true);
            } else {
                sendStatus.textContent = `发送失败: ${data.message}`;
            }
        } catch (error) {
            sendStatus.textContent = `发送错误: ${error.message}`;
        }
    });
    msgInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendBtn.click();
        }
    });

    // Pair (Create/Join Group)
    pairBtn.addEventListener('click', async () => {
        const gid = pairGidInput.value.trim();
        const cid = pairCidInput.value.trim(); // Optional

        if (!gid) {
            pairStatus.textContent = '群组ID不能为空。';
            return;
        }
        pairStatus.textContent = '';

        try {
            // If cid is provided, it's an invitation. Otherwise, it's creating/joining for self.
            // The backend /pair endpoint handles both creating a new group if it doesn't exist
            // (when cid is the current user or empty and the group is new to them)
            // or adding a specific cid to an existing group.
            // For UI simplicity, we'll assume if cid is empty, it's for the current user to join/create.
            // The backend logic `client.handshake(r.cid, r.gid)` seems to imply r.cid is the target to add.
            // If we want to create a group for ourselves, we might need a different endpoint or logic.
            // Based on prompt: "pair函数可用于创建一个群组，当群组不存在时"
            // Let's assume if cid is empty, it means the current user is trying to create/join.
            // The backend client.py handshake(target_cid, gid) might need adjustment or clarification
            // if target_cid is mandatory for group creation by oneself.
            // For now, we'll pass currentUsername if cid is empty, assuming handshake can handle it.
            const targetCid = cid || currentUsername; 

            const data = await apiCall('/pair', 'POST', { gid, cid: targetCid });
            if (data.status) {
                pairStatus.textContent = `操作成功: ${data.message || '已加入/创建群组或邀请已发送'}`;
                pairGidInput.value = '';
                pairCidInput.value = '';
                updateLists(); // Refresh lists
            } else {
                pairStatus.textContent = `操作失败: ${data.message}`;
            }
            setTimeout(() => pairStatus.textContent = '', 3000);
        } catch (error) {
            pairStatus.textContent = `操作错误: ${error.message}`;
            setTimeout(() => pairStatus.textContent = '', 3000);
        }
    });

    // Receive Messages
    async function fetchMessages() {
        if (!selectedGid) return; // Don't fetch if no group is selected
        try {
            const newMessages = await apiCall('/receive', 'GET');
            if (newMessages && newMessages.length > 0) {
                newMessages.forEach(msg => {
                    // Only display messages for the currently selected group
                    if (msg.group_id === selectedGid) {
                         appendMessage(msg, msg.uid === currentUsername);
                    }
                });
            }
        } catch (error) {
            console.error('获取消息失败:', error);
        }
    }

    function appendMessage(msg, isSentByCurrentUser) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message');
        messageElement.classList.add(isSentByCurrentUser ? 'sent' : 'received');

        const senderSpan = document.createElement('div');
        senderSpan.classList.add('sender');
        senderSpan.textContent = msg.uid;

        const contentSpan = document.createElement('div');
        contentSpan.classList.add('content');
        contentSpan.textContent = msg.content; // Assuming msg.content for text, adjust if it's msg.msg

        // const timestampSpan = document.createElement('div');
        // timestampSpan.classList.add('timestamp');
        // timestampSpan.textContent = new Date(msg.timestamp).toLocaleTimeString();
        
        messageElement.appendChild(senderSpan);
        messageElement.appendChild(contentSpan);
        // messageElement.appendChild(timestampSpan);
        
        messagesDiv.appendChild(messageElement);
        messagesDiv.scrollTop = messagesDiv.scrollHeight; // Scroll to bottom
    }

    // Update Lists (Clients, Groups)
    async function updateLists() {
        try {
            const [clients, groups, available] = await Promise.all([
                apiCall('/clients', 'GET'),
                apiCall('/groups', 'GET'),
                apiCall('/available_groups', 'GET')
            ]);

            populateList(clientsList, clients, clientsCount, 'client', (cid) => {
                // Optional: action when a client is clicked, e.g., prefill pair cid
                pairCidInput.value = cid;
            });
            populateList(allGroupsList, groups, allGroupsCount, 'group', selectGroup);
            populateList(availableGroupsList, available, availableGroupsCount, 'group', selectGroup, true);

        } catch (error) {
            console.error('更新列表失败:', error);
        }
    }

    function populateList(ulElement, items, countElement, itemType, onClickCallback, markActive = false) {
        ulElement.innerHTML = ''; // Clear existing items
        if (items && items.length > 0) {
            items.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                li.dataset.id = item;
                if (itemType === 'group' && markActive && item === selectedGid) {
                    li.classList.add('active-group');
                }
                li.addEventListener('click', () => onClickCallback(item));
                ulElement.appendChild(li);
            });
        }
        countElement.textContent = items ? items.length : 0;
    }

    function selectGroup(gid) {
        if (selectedGid === gid) return; // Already selected

        selectedGid = gid;
        currentGroupIdSpan.textContent = gid;
        messagesDiv.innerHTML = ''; // Clear messages from previous group
        
        // Highlight active group in the 'available groups' list
        document.querySelectorAll('#available-groups-list li').forEach(li => {
            if (li.dataset.id === gid) {
                li.classList.add('active-group');
            } else {
                li.classList.remove('active-group');
            }
        });
        // Highlight in 'all groups' list if it exists there too
         document.querySelectorAll('#all-groups-list li').forEach(li => {
            if (li.dataset.id === gid) {
                li.classList.add('active-group');
            } else {
                li.classList.remove('active-group');
            }
        });

        fetchMessages(); // Fetch messages for the new group
    }

    // Polling
    function startPolling() {
        stopPolling(); // Clear any existing intervals
        // Fetch messages more frequently
        messagePollingInterval = setInterval(fetchMessages, 1000); 
        // Update lists less frequently
        listUpdateInterval = setInterval(updateLists, 5000);
        updateLists(); // Initial call
    }

    function stopPolling() {
        if (messagePollingInterval) clearInterval(messagePollingInterval);
        if (listUpdateInterval) clearInterval(listUpdateInterval);
        messagePollingInterval = null;
        listUpdateInterval = null;
    }

    // Check login status on page load
    async function checkLoginStatus() {
        console.log('Checking login status...');
        try {
            const data = await apiCall('/status', 'GET');
            console.log('Status API response:', data);
            if (data.logged_in && data.username) {
                console.log('User is logged in. Username:', data.username);
                currentUsername = data.username;
                currentUserSpan.textContent = data.username;
                loginView.style.display = 'none';
                chatView.style.display = 'flex';
                console.log('Login view display:', loginView.style.display);
                console.log('Chat view display:', chatView.style.display);
                startPolling();
            } else {
                console.log('User is not logged in or username missing. Data:', data);
                loginView.style.display = 'flex';
                chatView.style.display = 'none';
                console.log('Login view display (not logged in):', loginView.style.display);
                console.log('Chat view display (not logged in):', chatView.style.display);
            }
        } catch (error) {
            console.error('Error checking login status:', error);
            loginView.style.display = 'flex';
            chatView.style.display = 'none';
            console.log('Login view display (error):', loginView.style.display);
            console.log('Chat view display (error):', chatView.style.display);
        }
    }

    // Initial state: check status then show appropriate view
    checkLoginStatus();
});