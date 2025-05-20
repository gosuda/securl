export interface UrlInfo {
  shortUrl: string;
  // Add other properties of UrlInfo here if needed
  Flags: Flags;
}

export enum Flags {
  None = 0,
  Captcha = 1 << 0, // 1
  Password = 1 << 1, // 2
  // Add other flags as powers of 2
}