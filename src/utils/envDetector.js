/**
 * DIS — Environment Auto-Detector v1.1
 * IrsanAI Stack · github.com/IrsanAI/IrsanAI-dis-core
 * Erkennt: Termux · Windows PS/CMD · Linux · macOS · Python
 */

export const ENV_TYPES = {
  TERMUX:         'termux',
  WINDOWS_PS:     'windows_powershell',
  WINDOWS_CMD:    'windows_cmd',
  LINUX_BASH:     'linux_bash',
  MACOS_ZSH:      'macos_zsh',
  PYTHON_CONSOLE: 'python_console',
  UNKNOWN:        'unknown'
};

export const SHELL_TYPES = {
  BASH:       'bash',
  ZSH:        'zsh',
  POWERSHELL: 'powershell',
  CMD:        'cmd',
  PYTHON:     'python',
  UNKNOWN:    'unknown'
};

export async function detectEnvironment() {
  const ua  = navigator.userAgent || '';
  const plt = (navigator.platform || '').toLowerCase();

  const base = {
    type:       ENV_TYPES.UNKNOWN,
    shell:      SHELL_TYPES.UNKNOWN,
    platform:   plt,
    userAgent:  ua,
    isMobile:   /Android|iPhone|iPad|iPod/i.test(ua),
    hasTermux:  false,
    hasPython:  false,
    hasPowershell: false,
    hasBash:    false,
    canExecute: false,
    pathSep:    '/',
    tempDir:    '/tmp',
    homeDir:    '~',
    scriptExt:  '.sh',
    interpreter:'bash',
    fallbacks:  []
  };

  // ── Termux ────────────────────────────────────────
  const termuxSignals = [
    ua.includes('Termux'),
    plt.includes('linux') && ua.includes('Android'),
    typeof process !== 'undefined' && !!process?.env?.TERMUX_VERSION
  ];
  if (termuxSignals.some(Boolean)) {
    return {
      ...base,
      type:       ENV_TYPES.TERMUX,
      shell:      SHELL_TYPES.BASH,
      hasTermux:  true,
      hasBash:    true,
      canExecute: true,
      tempDir:    '/data/data/com.termux/files/home/.dis/tmp',
      homeDir:    '/data/data/com.termux/files/home',
      interpreter:'bash',
      fallbacks:  ['python3', 'python', 'sh']
    };
  }

  // ── Windows ───────────────────────────────────────
  if (plt.includes('win') || ua.includes('Windows')) {
    const isPS = ua.includes('PowerShell') || ua.includes('PSConsoleHost');
    return {
      ...base,
      type:          isPS ? ENV_TYPES.WINDOWS_PS : ENV_TYPES.WINDOWS_CMD,
      shell:         isPS ? SHELL_TYPES.POWERSHELL : SHELL_TYPES.CMD,
      hasPowershell: isPS,
      canExecute:    true,
      pathSep:       '\\',
      tempDir:       '%TEMP%',
      homeDir:       '%USERPROFILE%',
      scriptExt:     isPS ? '.ps1' : '.bat',
      interpreter:   isPS ? 'powershell' : 'cmd',
      fallbacks:     isPS ? ['cmd', 'wscript'] : ['powershell']
    };
  }

  // ── macOS ────────────────────────────────────────
  if (plt.includes('mac')) {
    return {
      ...base,
      type:       ENV_TYPES.MACOS_ZSH,
      shell:      SHELL_TYPES.ZSH,
      hasBash:    true,
      canExecute: true,
      scriptExt:  '.sh',
      interpreter:'zsh',
      fallbacks:  ['bash', 'sh', 'python3']
    };
  }

  // ── Linux ────────────────────────────────────────
  if (plt.includes('linux')) {
    return {
      ...base,
      type:       ENV_TYPES.LINUX_BASH,
      shell:      SHELL_TYPES.BASH,
      hasBash:    true,
      canExecute: true,
      scriptExt:  '.sh',
      interpreter:'bash',
      fallbacks:  ['sh', 'dash', 'python3']
    };
  }

  // ── Python / Jupyter ─────────────────────────────
  if (typeof window !== 'undefined' &&
      (window.__IPYTHON__ || window.google?.colab || ua.includes('Jupyter'))) {
    return {
      ...base,
      type:       ENV_TYPES.PYTHON_CONSOLE,
      shell:      SHELL_TYPES.PYTHON,
      hasPython:  true,
      canExecute: true,
      scriptExt:  '.py',
      interpreter:'python3',
      fallbacks:  ['bash', 'sh']
    };
  }

  // ── Unknown Fallback ─────────────────────────────
  console.warn('⚠️ DIS: Environment unknown — using fallback chain');
  return { ...base, fallbacks: ['bash', 'sh', 'python3', 'cmd'] };
}

export function detectEnvironmentSync() {
  const ua  = typeof navigator !== 'undefined' ? (navigator.userAgent || '') : '';
  const plt = typeof navigator !== 'undefined' ? (navigator.platform  || '').toLowerCase() : '';

  const isWin     = plt.includes('win') || ua.includes('Windows');
  const isMac     = plt.includes('mac');
  const isAndroid = ua.includes('Android');
  const isTermux  = isAndroid && plt.includes('linux');

  if (isTermux)  return { type: ENV_TYPES.TERMUX,      shell: SHELL_TYPES.BASH,       pathSep:'/',  scriptExt:'.sh',  interpreter:'bash',        fallbacks:['python3','sh'],    canExecute:true };
  if (isWin)     return { type: ENV_TYPES.WINDOWS_PS,   shell: SHELL_TYPES.POWERSHELL, pathSep:'\\', scriptExt:'.ps1', interpreter:'powershell',   fallbacks:['cmd','wscript'],   canExecute:true };
  if (isMac)     return { type: ENV_TYPES.MACOS_ZSH,    shell: SHELL_TYPES.ZSH,        pathSep:'/',  scriptExt:'.sh',  interpreter:'zsh',          fallbacks:['bash','python3'],  canExecute:true };
  return           { type: ENV_TYPES.LINUX_BASH,  shell: SHELL_TYPES.BASH,       pathSep:'/',  scriptExt:'.sh',  interpreter:'bash',        fallbacks:['sh','python3'],    canExecute:true };
}
