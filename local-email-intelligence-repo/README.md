# Local Email Intelligence Repository

R1.1.39 uses a self-contained repository only. No third-party email corpus, phishing feed, URL reputation API, or external threat-intelligence service is bundled or required.

The seed contains locally authored defensive taxonomy and generic intent/mechanism pattern families only. It has `training_authority=false`; only explicit Mail Admin Ground Truth can create supervised training truth.

Runtime evidence grows from local sources already under administrator control: Postfix continuous delivery events, Amavis continuous evidence, quarantine history, delivered-mail observations, attachment/archive metadata, AI-vs-admin conflict investigations, and explicit Ground Truth.

Historical third-party repository rows already present in MariaDB are retained for audit/rollback safety but are deactivated by the new local seed. They are not deleted and are not used as the active repository.
