import { TokenStorage } from './token-storage';

describe('TokenStorage', () => {
  let storage: TokenStorage;

  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    storage = new TokenStorage();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('round-trips the refresh token', () => {
    expect(storage.getRefreshToken()).toBeNull();

    storage.setRefreshToken('refresh-1');

    expect(storage.getRefreshToken()).toBe('refresh-1');
  });

  it('keeps the token in sessionStorage, never in localStorage', () => {
    storage.setRefreshToken('refresh-1');

    expect(sessionStorage.length).toBe(1);
    expect(localStorage.length).toBe(0);
  });

  it('clears the token', () => {
    storage.setRefreshToken('refresh-1');

    storage.clear();

    expect(storage.getRefreshToken()).toBeNull();
  });

  it('degrades to "no token" when storage is unavailable', () => {
    const blocked = (): never => {
      throw new DOMException('The operation is insecure.', 'SecurityError');
    };
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(blocked);
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(blocked);
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(blocked);

    expect(() => storage.setRefreshToken('refresh-1')).not.toThrow();
    expect(storage.getRefreshToken()).toBeNull();
    expect(() => storage.clear()).not.toThrow();
  });
});
