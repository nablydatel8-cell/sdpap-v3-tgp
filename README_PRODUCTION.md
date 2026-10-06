# SDPAP v3 & TGP Protocol: Keyless Zero-Trust Architecture

## Архитектура бесключевой полной детерминированной верификации (Keyless Zero-Trust Architecture)

Система **SDPAP v3 (Secure Deterministic Proof-Carrying Architecture Protocol)** и протокол **TGP (Topological Gating Protocol)** полностью избавлены от внешних ключей доступа, приватных/публичных ключей Ed25519 и связанных с ними рисков компрометации ключей или управления сертификатами.

### Ключевые барьеры исполнения (4-Level TGP Execution Gate):

1. **Level 1 Gate Barrier (`verify_hash_chain`)**:
   Проверка причинно-следственной связи и целостности детерминированного канонического хэша конверта (`canonical_hash({"version", "nonce", "payload"})`).
2. **Level 2 (OCC & Replay Guard)**:
   Проверка уникальности одноразовых токенов `nonce` и непрерывного версионирования `StateVersion` для предотвращения повторных атак и гонок.
3. **Level 3 (Gate-Side Independent Graph Recomputation)**:
   Изолированный пересчет графа трансформации на стороне шлюза (оператор $M$) для полного исключения уязвимостей TOCTOU.
4. **Level 4 (Physical & Epistemological Invariants)**:
   Проверка физических инвариантов (фотонный $Q$-фактор резонатора $Q \ge 10^4$, расчет энергозатрат в Джоулях) и попперовская фальсифицируемость.

### База данных и неизменяемый реестр (Tamper-Evident Ledger):
* **SQLite WAL Mode**: Журнал предварительной записи с режимом блокировки `BEGIN EXCLUSIVE`.
* **Append-Only Triggers**: Триггеры `trg_prevent_update` и `trg_prevent_delete`, блокирующие любые операции модификации или удаления записей на уровне СУБД.
* **Merkle Tree & Green Anchor**: Автоматическое построение дерева Меркла и экспорт сертификата `Green Anchor` для внешнего публичного якорения.

## Команды утилиты управления (`sdpap_cli.py`)

* Инициализация базы данных:
  ```bash
  python3 sdpap_cli.py init-db
  ```
* Сборка канонического конверта:
  ```bash
  python3 sdpap_cli.py build-req --version 1 --nonce "unique_nonce" --payload '{"target_node":"node1","required_permission":"execute_core","metric_value":42.0}' --out req.json
  ```
* Отправка запроса в TGP Gate:
  ```bash
  python3 sdpap_cli.py submit --file req.json
  ```
* Запуск сквозного аудита целостности:
  ```bash
  python3 sdpap_cli.py audit
  ```
* Экспорт сертификата Зеленого Якоря:
  ```bash
  python3 sdpap_cli.py anchor --out anchor.json
  ```
* Генерация и проверка Merkle Proof:
  ```bash
  python3 sdpap_cli.py proof --sequence 1
  ```
