const pages = {
    home: `
        <section class="hero">
            <figure class="hero__image-wrapper">
                <img src="screen0.png" alt="SirisUnlocker" class="hero__image" loading="lazy" width="900" height="560">
            </figure>
            <h1 class="hero__title">SirisUnlocker</h1>
            <p class="hero__subtitle">Портативный инструмент для снятия ограничений,<br>управления автозагрузкой и процессами в Windows 10/11</p>
            <button class="btn btn--primary open-modal-btn">Скачать Siris</button>
        </section>
    `,
    about: `
        <section class="page-section">
            <h2 class="section-title">О программе</h2>
            <div class="about-grid stagger">
                <div class="card"><h3 class="card__title">Что такое SirisUnlocker?</h3><p class="card__text"><strong>SirisUnlocker</strong> — портативный инструмент для управления системой, снятия ограничений и контроля автозагрузки в <strong>Windows 10/11</strong>.</p></div>
                <div class="card"><h3 class="card__title">Ключевые возможности</h3><p class="card__text">• <strong>Древовидный диспетчер задач</strong><br>• <strong>Контроль автозагрузки</strong><br>• <strong>Снятие ограничений</strong><br>• <strong>Карантин</strong><br>• <strong>Горячие клавиши</strong><br>• <strong>Тёмный интерфейс</strong></p></div>
            </div>
        </section>
    `,
    features: `
        <section class="page-section">
            <h2 class="section-title">Возможности</h2>
            <div class="features-grid stagger">
                <div class="feature-card"><div class="feature-card__icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div><h3 class="feature-card__title">Диспетчер задач</h3><p class="feature-card__desc">Древовидное представление процессов.</p></div>
                <div class="feature-card"><div class="feature-card__icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L3 7v5c0 5.25 3.83 10.15 9 12 5.17-1.85 9-6.75 9-12V7l-9-5z"/></svg></div><h3 class="feature-card__title">Автозагрузка</h3><p class="feature-card__desc">Полный контроль реестра и служб.</p></div>
                <div class="feature-card"><div class="feature-card__icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg></div><h3 class="feature-card__title">Снятие ограничений</h3><p class="feature-card__desc">Разблокировка в один клик.</p></div>
                <div class="feature-card"><div class="feature-card__icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><h3 class="feature-card__title">Карантин</h3><p class="feature-card__desc">Изоляция и восстановление файлов.</p></div>
                <div class="feature-card"><div class="feature-card__icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><h3 class="feature-card__title">Горячие клавиши</h3><p class="feature-card__desc">Alt + \` для быстрого доступа.</p></div>
                <div class="feature-card"><div class="feature-card__icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></div><h3 class="feature-card__title">Доп. инструменты</h3><p class="feature-card__desc">Восстановление шрифтов и настроек.</p></div>
            </div>
        </section>
    `,
    screens: `
        <section class="page-section">
            <h2 class="section-title">Скриншоты</h2>
            <div class="screens-grid stagger">
                <div class="screenshot-card" data-src="screen1.png"><img src="screen1.png" alt="Диспетчер задач" class="screenshot-card__image" loading="lazy"><div class="screenshot-card__label">Диспетчер задач</div></div>
                <div class="screenshot-card" data-src="screen2.png"><img src="screen2.png" alt="Автозагрузка" class="screenshot-card__image" loading="lazy"><div class="screenshot-card__label">Управление автозагрузкой</div></div>
                <div class="screenshot-card" data-src="screen3.png"><img src="screen3.png" alt="Снятие ограничений" class="screenshot-card__image" loading="lazy"><div class="screenshot-card__label">Снятие ограничений</div></div>
                <div class="screenshot-card" data-src="screen4.png"><img src="screen4.png" alt="Карантин" class="screenshot-card__image" loading="lazy"><div class="screenshot-card__label">Карантин и восстановление</div></div>
                <div class="screenshot-card" data-src="screen5.png"><img src="screen5.png" alt="Дополнительные инструменты" class="screenshot-card__image" loading="lazy"><div class="screenshot-card__label">Дополнительные инструменты</div></div>
            </div>
        </section>
    `,
    changelog: `
        <section class="page-section">
            <h2 class="section-title">История изменений</h2>
            <div class="changelog" id="changelog-container">
                <div class="skeleton-entry"><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span></div>
                <div class="skeleton-entry"><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span></div>
                <div class="skeleton-entry"><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span></div>
            </div>
            <p class="changelog-footer">Полный список на <a href="https://github.com/DiscoD3979/Siris-Unlocker/releases" target="_blank" rel="noopener">GitHub Releases</a></p>
        </section>
    `,
    download: `
        <section class="page-section">
            <h2 class="section-title">Скачать SirisUnlocker</h2>
            <div class="download-grid stagger">
                <div class="download-card">
                    <h3 class="download-card__title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10"/></svg> Сайт</h3>
                    <ul class="download-card__list"><li>Прямая загрузка</li><li>Всегда актуально</li></ul>
                    <button class="btn btn--site desktop-only" id="downloadSiteBtn">Скачать с сайта</button>
                </div>
                <div class="download-card">
                    <h3 class="download-card__title"><svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12z"/></svg> GitHub</h3>
                    <ul class="download-card__list"><li>Последние обновления</li><li>Все релизы</li><li>Исходный код</li></ul>
                    <a href="https://github.com/DiscoD3979/Siris-Unlocker/releases/latest" target="_blank" rel="noopener" class="btn btn--github">Перейти на GitHub</a>
                </div>
                <div class="download-notice">⚠️ Загрузка .exe доступна только с компьютера. На телефоне используйте GitHub.</div>
            </div>
        </section>
    `,
    creator: `
        <section class="page-section">
            <h2 class="section-title">Создатель</h2>
            <div class="creator-grid stagger">
                <div class="card"><h3 class="card__title">DiscoD3979</h3><div class="typing-text" id="typing-text"></div><p class="card__text">Python-разработчик · Веб-разработчик · Автор SirisUnlocker</p></div>
                <div class="card"><h3 class="card__title">Мой ПК</h3><ul class="specs-list"><li><strong>CPU:</strong> i5-12400F</li><li><strong>GPU:</strong> RTX 3050 8GB</li><li><strong>RAM:</strong> 16 GB DDR4</li><li><strong>SSD:</strong> 512 GB NVMe</li></ul></div>
                <div class="card creator-card--full"><h3 class="card__title">Ссылки</h3><div class="links-grid">
                    <a href="https://github.com/DiscoD3979" target="_blank" class="link-item"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12z"/></svg> GitHub</a>
                    <a href="https://steamcommunity.com/id/DiscoD3979/" target="_blank" class="link-item"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12.004 2c-5.25 0-9.556 4.05-9.964 9.197l5.36 2.216c.454-.31 1.002-.492 1.593-.492.053 0 .104.003.157.005l2.384-3.452v-.049c0-2.08 1.69-3.77 3.77-3.77 2.079 0 3.77 1.692 3.77 3.772s-1.692 3.771-3.77 3.771h-.087l-3.397 2.426c0 .043.003.088.003.133 0 1.562-1.262 2.83-2.825 2.83-1.362 0-2.513-.978-2.775-2.273l-3.838-1.589C3.573 18.922 7.427 22 12.005 22c5.522 0 9.998-4.477 9.998-10 0-5.522-4.477-10-9.999-10z"/></svg> Steam</a>
                    <a href="https://t.me/MemesSrd" target="_blank" class="link-item"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg> Telegram</a>
                </div></div>
            </div>
        </section>
    `,
    admin: `
        <section class="page-section">
            <h2 class="section-title">Админ-панель</h2>
            <div id="adminLogin" class="admin-login">
                <div class="card admin-card" style="max-width: 400px; margin: 0 auto;">
                    <div class="admin-art">
                        <img src="artik.png" alt="" class="admin-art__img" loading="lazy">
                    </div>
                    <h3 class="card__title" style="text-align: center;">Вход</h3>
                    <div class="admin-form">
                        <div class="password-wrapper">
                            <input type="password" id="adminPass" class="admin-input" placeholder="Пароль" autocomplete="off">
                            <button class="password-toggle" id="passwordToggle" type="button" aria-label="Показать пароль">👁</button>
                        </div>
                        <button class="btn btn--primary" style="width:100%; margin-top: 4px;" id="adminLoginBtn">Войти</button>
                        <p class="admin-error" id="adminError" style="color:var(--accent);font-size:13px;margin-top:8px;display:none;">Неверный пароль</p>
                    </div>
                </div>
            </div>
            <div id="adminPanel" class="admin-panel" style="display:none;">
                <div class="admin-dashboard">
                    <div class="admin-dashboard__grid">
                        <div class="card admin-card-dash" id="adminCardGithub">
                            <div class="admin-card-dash__header">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12z"/></svg>
                                <span>Последний релиз GitHub</span>
                            </div>
                            <div id="adminGithubContent" class="admin-card-dash__body">
                                <div class="admin-skeleton"><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span></div>
                            </div>
                        </div>
                        <div class="card admin-card-dash" id="adminCardUploaded">
                            <div class="admin-card-dash__header">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                                <span>Загружено на сайт</span>
                            </div>
                            <div id="adminUploadedContent" class="admin-card-dash__body">
                                <p class="admin-empty">Нет загруженных файлов</p>
                            </div>
                        </div>
                        <div class="card admin-card-dash admin-card-dash--wide" id="adminCardUpload">
                            <div class="admin-card-dash__header">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/><polyline points="16 16 12 12 8 16"/></svg>
                                <span>Загрузить новый релиз</span>
                            </div>
                            <div class="admin-card-dash__body">
                                <div class="file-upload-area" id="dropZone">
                                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                                    <p>Перетащите файл сюда или нажмите для выбора</p>
                                    <p class="file-hint">Только .exe файлы</p>
                                </div>
                                <input type="file" id="fileInput" accept=".exe" style="display:none;">
                                <div id="fileInfo" class="file-info" style="display:none;"><span id="fileName"></span><span id="fileSize"></span></div>
                                <button class="btn btn--primary" id="uploadBtn" style="width:100%;margin-top:12px;" disabled>Загрузить</button>
                                <div class="upload-progress-wrap" id="progressWrap" style="display:none;"><div class="upload-progress-bar"><div class="upload-progress-fill" id="progressFill"></div></div><div class="upload-progress-text" id="progressText">Готово 0%</div></div>
                                <div id="uploadStatus" class="upload-status"></div>
                            </div>
                        </div>
                        <div class="card admin-card-dash" id="adminCardActions">
                            <div class="admin-card-dash__header">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                                <span>Действия</span>
                                <span class="session-timer" id="sessionTimer"></span>
                            </div>
                            <div class="admin-card-dash__body admin-actions">
                                <div class="admin-card-dash__header" style="font-size:13px;color:var(--text-secondary);border-bottom:none;padding-bottom:0;margin-bottom:8px;">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                                    Настройки Netlify (авто-деплой)
                                </div>
                                <div class="admin-form" id="netlifySettings">
                                    <input type="password" id="netlifyToken" class="admin-input" placeholder="Netlify Personal Access Token">
                                    <input type="text" id="netlifySiteId" class="admin-input" placeholder="Название сайта (sirisunlocker)">
                                    <button class="btn btn--github" id="netlifySaveBtn" style="width:100%;">Сохранить</button>
                                    <div id="netlifyStatus" class="upload-status" style="font-size:13px;"></div>
                                </div>
                                <hr style="border:none;border-top:1px solid var(--border);margin:12px 0;">
                                <button class="btn btn--github" id="adminDeleteBtn" style="width:100%;" disabled>
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                    Удалить загруженный файл
                                </button>
                                <button class="btn btn--github" id="adminLogoutBtn" style="width:100%;">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                                    Выйти
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    `
};