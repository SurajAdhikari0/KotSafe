/**
 * KotSafe Internationalization (i18n) System
 * Copyright (c) 2026 KotSafe Cyber Security Project
 */

export type Locale = 'en' | 'es' | 'de' | 'fr' | 'ar' | 'ja';

export interface Translations {
  activationTitle: string;
  activationSubtitle: string;
  statusCardTitle: string;
  planLabel: string;
  licenseKeyLabel: string;
  activationDateLabel: string;
  expiryDateLabel: string;
  seatsLabel: string;
  lastVerifiedLabel: string;
  freemiumNoticeTitle: string;
  freemiumNoticeDesc: string;
  upgradeBtn: string;
  buyLicenseLink: string;
  inputLabel: string;
  inputPlaceholder: string;
  inputHelper: string;
  activateBtn: string;
  activatingBtn: string;
  showKey: string;
  hideKey: string;
  pasteBtn: string;
  pasteSuccess: string;
  pasteError: string;
  revalidateBtn: string;
  revalidatingBtn: string;
  deactivateBtn: string;
  manageLicenseLink: string;
  renewLink: string;
  deactivateModalTitle: string;
  deactivateModalBody: string;
  deactivateModalConfirm: string;
  deactivateModalCancel: string;
  activationSuccessToast: string;
  deactivationSuccessToast: string;
  revalidationSuccessToast: string;
  gracePeriodWarning: string;
  cooldownMessage: string;
  featureComparisonTitle: string;
  freeTierName: string;
  proTierName: string;
  features: {
    p2pLimit: string;
    aiDefense: string;
    yaraScan: string;
    pcapExport: string;
    cloudMesh: string;
  };
}

export const translations: Record<Locale, Translations> = {
  en: {
    activationTitle: 'License Activation',
    activationSubtitle: 'Manage your KotSafe subscription, device seats, and cyber defense entitlements',
    statusCardTitle: 'Subscription Status',
    planLabel: 'Current Plan',
    licenseKeyLabel: 'License Key',
    activationDateLabel: 'Activated On',
    expiryDateLabel: 'Valid Until',
    seatsLabel: 'Active Devices',
    lastVerifiedLabel: 'Last Verified',
    freemiumNoticeTitle: 'Unlock Full Cybersecurity Protection',
    freemiumNoticeDesc: 'You are using KotSafe Freemium. Upgrade to Pro for autonomous AI malware interception, YARA scan, and multi-device P2P exit nodes.',
    upgradeBtn: 'Upgrade to Pro',
    buyLicenseLink: 'Buy License &rarr;',
    inputLabel: 'Enter Activation License Key',
    inputPlaceholder: 'KOT-PRO-XXXXX-XXXXX',
    inputHelper: 'Enter your 21-character activation key (e.g. KOT-PRO-ABCD1234-EF56)',
    activateBtn: 'Activate Device',
    activatingBtn: 'Activating...',
    showKey: 'Show key',
    hideKey: 'Hide key',
    pasteBtn: 'Paste',
    pasteSuccess: 'Key pasted from clipboard',
    pasteError: 'Unable to access clipboard. Please paste manually.',
    revalidateBtn: 'Re-validate Now',
    revalidatingBtn: 'Checking...',
    deactivateBtn: 'Deactivate This Device',
    manageLicenseLink: 'Manage License Portal',
    renewLink: 'Renew Now &rarr;',
    deactivateModalTitle: 'Deactivate Device License?',
    deactivateModalBody: 'Are you sure you want to deactivate KotSafe Pro on this device? This will release 1 seat back to your license pool. Premium defense engines will immediately revert to the Freemium tier.',
    deactivateModalConfirm: 'Yes, Deactivate Device',
    deactivateModalCancel: 'Keep License',
    activationSuccessToast: 'KotSafe license successfully activated! All security engines unlocked.',
    deactivationSuccessToast: 'Device successfully deactivated. Reverted to Freemium tier.',
    revalidationSuccessToast: 'License status verified with cloud security server.',
    gracePeriodWarning: 'Offline Grace Period: Server unreachable. License valid offline for {days} more days.',
    cooldownMessage: 'Rate limited. Cooldown: {seconds}s remaining.',
    featureComparisonTitle: 'Feature Tier Comparison',
    freeTierName: 'Community (Free)',
    proTierName: 'Pro / Enterprise',
    features: {
      p2pLimit: 'P2P Exit Devices: 1 device vs up to 6 devices',
      aiDefense: 'AI Autonomous Defense: Basic vs Real-Time heuristic',
      yaraScan: 'YARA Memory Inspection: Locked vs Active',
      pcapExport: 'PCAPng Dissection: Standard vs Unlimited dumps',
      cloudMesh: 'Private Cloud Mesh: Standard vs Zero-latency relay',
    },
  },
  es: {
    activationTitle: 'Activación de Licencia',
    activationSubtitle: 'Administre su suscripción a KotSafe, dispositivos y licencias de ciberdefensa',
    statusCardTitle: 'Estado de la Suscripción',
    planLabel: 'Plan Actual',
    licenseKeyLabel: 'Clave de Licencia',
    activationDateLabel: 'Activado el',
    expiryDateLabel: 'Válido Hasta',
    seatsLabel: 'Dispositivos Activos',
    lastVerifiedLabel: 'Última Verificación',
    freemiumNoticeTitle: 'Desbloquear Protección Completa',
    freemiumNoticeDesc: 'Está usando KotSafe Freemium. Actualice a Pro para interceptación autónoma por IA y nodos P2P.',
    upgradeBtn: 'Actualizar a Pro',
    buyLicenseLink: 'Comprar Licencia &rarr;',
    inputLabel: 'Ingrese la Clave de Activación',
    inputPlaceholder: 'KOT-PRO-XXXXX-XXXXX',
    inputHelper: 'Ingrese su clave de 21 caracteres (ej. KOT-PRO-ABCD1234-EF56)',
    activateBtn: 'Activar Dispositivo',
    activatingBtn: 'Activando...',
    showKey: 'Mostrar clave',
    hideKey: 'Ocultar clave',
    pasteBtn: 'Pegar',
    pasteSuccess: 'Clave pegada del portapapeles',
    pasteError: 'No se puede acceder al portapapeles',
    revalidateBtn: 'Revalidar Ahora',
    revalidatingBtn: 'Comprobando...',
    deactivateBtn: 'Desactivar Este Dispositivo',
    manageLicenseLink: 'Portal de Gestión de Licencias',
    renewLink: 'Renovar Ahora &rarr;',
    deactivateModalTitle: '¿Desactivar Licencia del Dispositivo?',
    deactivateModalBody: '¿Está seguro de desactivar KotSafe Pro en este dispositivo? Se liberará 1 puesto de su licencia.',
    deactivateModalConfirm: 'Sí, Desactivar',
    deactivateModalCancel: 'Mantener Licencia',
    activationSuccessToast: '¡Licencia de KotSafe activada con éxito!',
    deactivationSuccessToast: 'Dispositivo desactivado. Vuelto al plan Freemium.',
    revalidationSuccessToast: 'Estado de la licencia verificado.',
    gracePeriodWarning: 'Período de gracia fuera de línea: {days} días restantes.',
    cooldownMessage: 'Tiempo de espera: {seconds}s restantes.',
    featureComparisonTitle: 'Comparación de Planes',
    freeTierName: 'Comunidad (Gratis)',
    proTierName: 'Pro / Enterprise',
    features: {
      p2pLimit: 'Dispositivos P2P: 1 dispositivo frente a 6',
      aiDefense: 'Defensa Autónoma IA: Básico frente a Tiempo Real',
      yaraScan: 'Inspección de Memoria YARA: Bloqueado frente a Activo',
      pcapExport: 'Captura PCAPng: Estándar frente a Ilimitado',
      cloudMesh: 'Malla en la Nube: Estándar frente a Cero Latencia',
    },
  },
  de: {
    activationTitle: 'Lizenzaktivierung',
    activationSubtitle: 'Verwalten Sie Ihr KotSafe-Abonnement, Geräteplätze und Sicherheitsstufen',
    statusCardTitle: 'Abonnementstatus',
    planLabel: 'Aktueller Tarif',
    licenseKeyLabel: 'Lizenzschlüssel',
    activationDateLabel: 'Aktiviert am',
    expiryDateLabel: 'Gültig bis',
    seatsLabel: 'Aktive Geräte',
    lastVerifiedLabel: 'Zuletzt geprüft',
    freemiumNoticeTitle: 'Vollen Schutz freischalten',
    freemiumNoticeDesc: 'Sie nutzen KotSafe Freemium. Upgraden Sie auf Pro für KI-Malware-Schutz und P2P-Exit-Knoten.',
    upgradeBtn: 'Auf Pro upgraden',
    buyLicenseLink: 'Lizenz kaufen &rarr;',
    inputLabel: 'Aktivierungsschlüssel eingeben',
    inputPlaceholder: 'KOT-PRO-XXXXX-XXXXX',
    inputHelper: 'Geben Sie Ihren 21-stelligen Schlüssel ein',
    activateBtn: 'Gerät aktivieren',
    activatingBtn: 'Aktivierung...',
    showKey: 'Schlüssel anzeigen',
    hideKey: 'Schlüssel verbergen',
    pasteBtn: 'Einfügen',
    pasteSuccess: 'Schlüssel eingefügt',
    pasteError: 'Zugriff auf Zwischenablage nicht möglich',
    revalidateBtn: 'Jetzt prüfen',
    revalidatingBtn: 'Prüfung...',
    deactivateBtn: 'Gerät deaktivieren',
    manageLicenseLink: 'Lizenzportal verwalten',
    renewLink: 'Jetzt verlängern &rarr;',
    deactivateModalTitle: 'Gerätelizenz deaktivieren?',
    deactivateModalBody: 'Möchten Sie KotSafe Pro auf diesem Gerät wirklich deaktivieren? Ein Platz wird freigegeben.',
    deactivateModalConfirm: 'Ja, deaktivieren',
    deactivateModalCancel: 'Abbrechen',
    activationSuccessToast: 'KotSafe-Lizenz erfolgreich aktiviert!',
    deactivationSuccessToast: 'Gerät deaktiviert. Zurück auf Freemium.',
    revalidationSuccessToast: 'Lizenzstatus erfolgreich verifiziert.',
    gracePeriodWarning: 'Offline-Kulanzzeit: Noch {days} Tage gültig.',
    cooldownMessage: 'Wartezeit: noch {seconds}s.',
    featureComparisonTitle: 'Funktionsvergleich',
    freeTierName: 'Community (Kostenlos)',
    proTierName: 'Pro / Enterprise',
    features: {
      p2pLimit: 'P2P-Knoten: 1 Gerät vs. bis zu 6 Geräte',
      aiDefense: 'Autonome KI-Abwehr: Basis vs. Echtzeit',
      yaraScan: 'YARA-Speicherprüfung: Gesperrt vs. Aktiv',
      pcapExport: 'PCAPng-Dumps: Standard vs. Unbegrenzt',
      cloudMesh: 'Private Cloud-Mesh: Standard vs. Null-Latenz',
    },
  },
  fr: {
    activationTitle: 'Activation de la Licence',
    activationSubtitle: 'Gérez votre abonnement KotSafe, vos postes et vos modules de cyberdéfense',
    statusCardTitle: 'Statut de l\'Abonnement',
    planLabel: 'Forfait Actuel',
    licenseKeyLabel: 'Clé de Licence',
    activationDateLabel: 'Activé le',
    expiryDateLabel: 'Valable Jusqu\'au',
    seatsLabel: 'Appareils Actifs',
    lastVerifiedLabel: 'Dernière Vérification',
    freemiumNoticeTitle: 'Débloquez la Protection Complète',
    freemiumNoticeDesc: 'Vous utilisez KotSafe Freemium. Passez à Pro pour l\'interception IA et les nœuds P2P.',
    upgradeBtn: 'Passer à Pro',
    buyLicenseLink: 'Acheter une Licence &rarr;',
    inputLabel: 'Entrez la Clé d\'Activation',
    inputPlaceholder: 'KOT-PRO-XXXXX-XXXXX',
    inputHelper: 'Entrez votre clé à 21 caractères',
    activateBtn: 'Activer l\'Appareil',
    activatingBtn: 'Activation...',
    showKey: 'Afficher la clé',
    hideKey: 'Masquer la clé',
    pasteBtn: 'Coller',
    pasteSuccess: 'Clé collée',
    pasteError: 'Impossible d\'accéder au presse-papier',
    revalidateBtn: 'Revérifier Maintenant',
    revalidatingBtn: 'Vérification...',
    deactivateBtn: 'Désactiver Cet Appareil',
    manageLicenseLink: 'Gérer la Licence',
    renewLink: 'Renouveler &rarr;',
    deactivateModalTitle: 'Désactiver la Licence?',
    deactivateModalBody: 'Voulez-vous vraiment désactiver KotSafe Pro sur cet appareil ? 1 place sera libérée.',
    deactivateModalConfirm: 'Oui, Désactiver',
    deactivateModalCancel: 'Conserver la Licence',
    activationSuccessToast: 'Licence KotSafe activée avec succès !',
    deactivationSuccessToast: 'Appareil désactivé. Retour à Freemium.',
    revalidationSuccessToast: 'Statut de la licence vérifié.',
    gracePeriodWarning: 'Période de grâce hors ligne : {days} jours restants.',
    cooldownMessage: 'Délai d\'attente : {seconds}s restantes.',
    featureComparisonTitle: 'Comparatif des Fonctionnalités',
    freeTierName: 'Communauté (Gratuit)',
    proTierName: 'Pro / Enterprise',
    features: {
      p2pLimit: 'Nœuds P2P : 1 appareil contre 6',
      aiDefense: 'Défense Autonome IA : Standard contre Temps Réel',
      yaraScan: 'Inspection Mémoire YARA : Verrouillé contre Actif',
      pcapExport: 'Export PCAPng : Standard contre Illimité',
      cloudMesh: 'Mesh Privé : Standard contre Zéro-latence',
    },
  },
  ar: {
    activationTitle: 'تفعيل الترخيص',
    activationSubtitle: 'إدارة اشتراك KotSafe وأجهزة الدفاع السيبراني الخاصة بك',
    statusCardTitle: 'حالة الاشتراك',
    planLabel: 'الخطة الحالية',
    licenseKeyLabel: 'مفتاح الترخيص',
    activationDateLabel: 'تاريخ التفعيل',
    expiryDateLabel: 'صالح حتى',
    seatsLabel: 'الأجهزة النشطة',
    lastVerifiedLabel: 'آخر تحقق',
    freemiumNoticeTitle: 'افتح الحماية السيبرانية الكاملة',
    freemiumNoticeDesc: 'أنت تستخدم النسخة المجانية. قم بالترقية إلى Pro للحصول على حماية الذكاء الاصطناعي الكاملة.',
    upgradeBtn: 'الترقية إلى Pro',
    buyLicenseLink: 'شراء ترخيص &rarr;',
    inputLabel: 'أدخل مفتاح الترخيص للتفعيل',
    inputPlaceholder: 'KOT-PRO-XXXXX-XXXXX',
    inputHelper: 'أدخل مفتاح التفعيل المكون من 21 حرفًا (مثل KOT-PRO-ABCD1234-EF56)',
    activateBtn: 'تفعيل الجهاز',
    activatingBtn: 'جاري التفعيل...',
    showKey: 'إظهار المفتاح',
    hideKey: 'إخفاء المفتاح',
    pasteBtn: 'لصق',
    pasteSuccess: 'تم لصق المفتاح من الحافظة',
    pasteError: 'تعذر الوصول إلى الحافظة',
    revalidateBtn: 'إعادة التحقق الآن',
    revalidatingBtn: 'جاري التحقق...',
    deactivateBtn: 'إلغاء تفعيل هذا الجهاز',
    manageLicenseLink: 'بوابة إدارة التراخيص',
    renewLink: 'تجديد الآن &rarr;',
    deactivateModalTitle: 'هل تريد إلغاء تفعيل ترخيص الجهاز؟',
    deactivateModalBody: 'هل أنت متأكد من إلغاء تفعيل KotSafe Pro على هذا الجهاز؟ سيتم تحرير مقعد واحد.',
    deactivateModalConfirm: 'نعم، إلغاء التفعيل',
    deactivateModalCancel: 'إلغاء',
    activationSuccessToast: 'تم تفعيل ترخيص KotSafe بنجاح!',
    deactivationSuccessToast: 'تم إلغاء تفعيل الجهاز. تم العودة إلى الخطة المجانية.',
    revalidationSuccessToast: 'تم التحقق من حالة الترخيص.',
    gracePeriodWarning: 'فترة السماح غير المتصلة: متبقي {days} أيام.',
    cooldownMessage: 'يرجى الانتظار: متبقي {seconds} ثانية.',
    featureComparisonTitle: 'مقارنة الميزات',
    freeTierName: 'مجاني',
    proTierName: 'Pro / Enterprise',
    features: {
      p2pLimit: 'أجهزة P2P: جهاز واحد مقابل 6 أجهزة',
      aiDefense: 'دفاع الذكاء الاصطناعي: أساسي مقابل فوري',
      yaraScan: 'فحص ذاكرة YARA: مقفل مقابل نشط',
      pcapExport: 'تصدير PCAPng: قياسي مقابل غير محدود',
      cloudMesh: 'شبكة سحابية خاصة: قياسي مقابل فائق السرعة',
    },
  },
  ja: {
    activationTitle: 'ライセンス認証',
    activationSubtitle: 'KotSafeのサブスクリプション、デバイスシート、サイバー防御機能を管理',
    statusCardTitle: 'サブスクリプション状態',
    planLabel: '現在のプラン',
    licenseKeyLabel: 'ライセンスキー',
    activationDateLabel: '認証日',
    expiryDateLabel: '有効期限',
    seatsLabel: '使用中デバイス',
    lastVerifiedLabel: '最終検証',
    freemiumNoticeTitle: '完全なセキュリティ機能を解放',
    freemiumNoticeDesc: '現在KotSafeフリーミアム版をご利用中です。Pro版へアップグレードしてAI自律防御やP2P出口ノードを解放してください。',
    upgradeBtn: 'Proへアップグレード',
    buyLicenseLink: 'ライセンスを購入 &rarr;',
    inputLabel: 'ライセンスキーを入力',
    inputPlaceholder: 'KOT-PRO-XXXXX-XXXXX',
    inputHelper: '21文字の認証キーを入力してください（例: KOT-PRO-ABCD1234-EF56）',
    activateBtn: 'デバイスを認証',
    activatingBtn: '認証中...',
    showKey: 'キーを表示',
    hideKey: 'キーを隠す',
    pasteBtn: '貼り付け',
    pasteSuccess: 'クリップボードから貼り付けました',
    pasteError: 'クリップボードにアクセスできません',
    revalidateBtn: '今すぐ再検証',
    revalidatingBtn: '検証中...',
    deactivateBtn: 'このデバイスの認証を解除',
    manageLicenseLink: 'ライセンス管理ポータル',
    renewLink: '今すぐ更新 &rarr;',
    deactivateModalTitle: 'デバイスの認証を解除しますか？',
    deactivateModalBody: 'このデバイスでKotSafe Proのライセンスを解除してもよろしいですか？1台分のシートがプールへ返却されます。',
    deactivateModalConfirm: 'はい、認証を解除',
    deactivateModalCancel: 'ライセンスを維持',
    activationSuccessToast: 'KotSafeライセンスの認証に成功しました！',
    deactivationSuccessToast: 'デバイスの認証を解除しました。フリー版に戻りました。',
    revalidationSuccessToast: 'ライセンス状態を検証しました。',
    gracePeriodWarning: 'オフライン猶予期間: 残り{days}日間有効です。',
    cooldownMessage: '試行回数制限中: 残り{seconds}秒',
    featureComparisonTitle: 'プラン別機能比較',
    freeTierName: 'コミュニティ（無料）',
    proTierName: 'Pro / Enterprise',
    features: {
      p2pLimit: 'P2P出口デバイス: 1台 vs 最大6台',
      aiDefense: 'AI自律防御: 基本 vs リアルタイム検知',
      yaraScan: 'YARAメモリ検査: ロック vs 有効',
      pcapExport: 'PCAPng解析: 標準 vs 無制限エクスポート',
      cloudMesh: 'プライベートメッシュ: 標準 vs 超低遅延リレー',
    },
  },
};

export function getTranslations(locale: Locale): Translations {
  return translations[locale] || translations.en;
}
