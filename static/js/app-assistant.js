(function () {
    function createMessage(container, text, isUser) {
        var node = document.createElement('div');
        node.className = isUser ? 'app-ai-user-msg' : 'app-ai-bot-msg';
        node.textContent = text;
        container.appendChild(node);
        container.scrollTop = container.scrollHeight;
        return node;
    }

    function sendFeedback(csrfToken, helpful, questionText, answerText) {
        var payload = new URLSearchParams();
        payload.set('helpful', helpful ? '1' : '0');
        payload.set('question', String(questionText || '').trim().slice(0, 500));
        payload.set('answer', String(answerText || '').trim().slice(0, 1200));
        payload.set('page', window.location.pathname || '/');
        if (csrfToken) payload.set('csrf_token', csrfToken);
        fetch('/assistant/feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: payload.toString()
        }).catch(function () {});
    }

    function renderFeedbackControls(csrfToken, hostNode, questionText, answerText) {
        if (!hostNode) return;
        var wrap = document.createElement('div');
        wrap.className = 'app-ai-feedback';
        var up = document.createElement('button');
        up.type = 'button';
        up.className = 'app-ai-feedback-btn';
        up.textContent = 'Helpful';
        var down = document.createElement('button');
        down.type = 'button';
        down.className = 'app-ai-feedback-btn';
        down.textContent = 'Not helpful';
        function applyChoice(isHelpful) {
            sendFeedback(csrfToken, isHelpful, questionText, answerText);
            up.disabled = true;
            down.disabled = true;
            if (isHelpful) up.classList.add('active');
            else down.classList.add('active');
        }
        up.addEventListener('click', function () { applyChoice(true); });
        down.addEventListener('click', function () { applyChoice(false); });
        wrap.appendChild(up);
        wrap.appendChild(down);
        hostNode.appendChild(wrap);
        hostNode.parentNode.scrollTop = hostNode.parentNode.scrollHeight;
    }

    function renderQuickPrompts(quickWrap, prompts, onPick) {
        quickWrap.innerHTML = '';
        (prompts || []).slice(0, 3).forEach(function (promptText) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.textContent = promptText;
            btn.addEventListener('click', function () {
                onPick(promptText);
            });
            quickWrap.appendChild(btn);
        });
    }

    function initAssistant(root) {
        if (!root || root.dataset.bound === '1') return;
        root.dataset.bound = '1';

        var panel = root.querySelector('.app-ai-panel');
        var toggle = root.querySelector('.app-ai-toggle');
        var closeBtn = root.querySelector('.app-ai-close');
        var form = root.querySelector('.app-ai-form');
        var input = form ? form.querySelector('input[name=\"question\"]') : null;
        var messages = root.querySelector('.app-ai-messages');
        var quickWrap = root.querySelector('.app-ai-quick');
        var csrfToken = (root.querySelector('.app-ai-csrf') || {}).value || '';

        if (!panel || !toggle || !closeBtn || !form || !input || !messages || !quickWrap) return;

        try {
            var pulseKey = 'app_ai_seen_pulse_v1';
            if (!window.localStorage.getItem(pulseKey)) {
                toggle.classList.add('app-ai-pulse');
                window.localStorage.setItem(pulseKey, '1');
                window.setTimeout(function () {
                    toggle.classList.remove('app-ai-pulse');
                }, 7600);
            }
        } catch (e) {}

        function openPanel() {
            panel.hidden = false;
            toggle.setAttribute('aria-expanded', 'true');
            input.focus();
        }

        function closePanel() {
            panel.hidden = true;
            toggle.setAttribute('aria-expanded', 'false');
        }

        function ask(questionText) {
            var text = String(questionText || '').trim();
            if (!text) return;
            createMessage(messages, text, true);
            createMessage(messages, 'Thinking...', false);
            var pendingNode = messages.lastElementChild;

            var payload = new URLSearchParams();
            payload.set('question', text);
            payload.set('page', window.location.pathname || '/');
            if (csrfToken) payload.set('csrf_token', csrfToken);

            fetch('/assistant/guide', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: payload.toString()
            }).then(function (resp) {
                if (!resp.ok) throw new Error('Assistant request failed.');
                return resp.json();
            }).then(function (data) {
                if (pendingNode && pendingNode.parentNode) pendingNode.parentNode.removeChild(pendingNode);
                if (!data || !data.ok) {
                    createMessage(messages, 'I could not process that. Try again.', false);
                    return;
                }
                var lines = [data.answer || 'I could not find a direct answer.'];
                if (Array.isArray(data.steps) && data.steps.length) {
                    data.steps.slice(0, 4).forEach(function (step, idx) {
                        lines.push((idx + 1) + '. ' + step);
                    });
                }
                if (Array.isArray(data.links) && data.links.length) {
                    lines.push('Useful pages: ' + data.links.map(function (item) { return item.label; }).join(', '));
                }
                var answerText = lines.join('\n');
                var botNode = createMessage(messages, answerText, false);
                renderFeedbackControls(csrfToken, botNode, text, answerText);
                renderQuickPrompts(quickWrap, data.quick_prompts || [], function (picked) {
                    ask(picked);
                });
            }).catch(function () {
                if (pendingNode && pendingNode.parentNode) pendingNode.parentNode.removeChild(pendingNode);
                createMessage(messages, 'Network or permission issue. Please try again.', false);
            });
        }

        toggle.addEventListener('click', function () {
            if (panel.hidden) openPanel();
            else closePanel();
        });
        closeBtn.addEventListener('click', closePanel);
        form.addEventListener('submit', function (ev) {
            ev.preventDefault();
            ask(input.value);
            input.value = '';
        });

        renderQuickPrompts(quickWrap, [
            'How do I use messages?',
            'How do I change password?',
            'Where is help page?'
        ], function (picked) {
            if (panel.hidden) openPanel();
            ask(picked);
        });

        // Always start collapsed and open only on user click.
        closePanel();
    }

    function boot() {
        var welcomeNode = document.querySelector('.app-welcome-toast');
        if (welcomeNode) {
            window.setTimeout(function () {
                welcomeNode.classList.add('app-welcome-hide');
                window.setTimeout(function () {
                    if (welcomeNode && welcomeNode.parentNode) welcomeNode.parentNode.removeChild(welcomeNode);
                }, 380);
            }, 10000);
        }
        var roots = document.querySelectorAll('.app-ai-assistant');
        roots.forEach(initAssistant);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
