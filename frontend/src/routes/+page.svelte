<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/stores";

  import type { UrlInfo } from "$lib/types";
  import { Flags } from "$lib/types";

  let showShortenForm = true;
  let urlInfo: UrlInfo | null = null;
  let longUrl = "";
  let passwordEnabled = false;
  let captchaForced = false;
  let passwordInput = ""; // State for password input
  let showPasswordInput = false; // State to control password input visibility

  // Function to fetch URL info based on hash (simulated)
  async function getUrlInfoFromHash(hash: string): Promise<UrlInfo | null> {
    // In a real application, this would be an API call to the backend
    console.log("Fetching URL info for hash:", hash);
    // Simulate fetching data
    await new Promise((resolve) => setTimeout(resolve, 100)); // Simulate network delay

    // Simulate different scenarios based on hash
    if (hash === "password_protected") {
      return {
        shortUrl: hash,
        Flags: Flags.Password,
      };
    } else if (hash === "captcha_required") {
      return {
        shortUrl: hash,
        Flags: Flags.Captcha,
      };
    } else if (hash === "password_and_captcha") {
      return {
        shortUrl: hash,
        Flags: Flags.Password | Flags.Captcha,
      };
    } else if (hash === "simulated_short_url") {
      return {
        shortUrl: hash,
        Flags: Flags.None,
      };
    }
    // Default case for a simple shortened URL
    return {
      shortUrl: hash,
      Flags: Flags.None,
    };
  }

  onMount(async () => {
    // Check if there is a hash in the URL
    if ($page.url.hash) {
      showShortenForm = false;
      const hash = $page.url.hash.substring(1); // Remove the '#'
      urlInfo = await getUrlInfoFromHash(hash);

      // Check flags and show password input if needed
      if (urlInfo?.Flags && urlInfo.Flags & Flags.Password) {
        showPasswordInput = true;
      }
    } else {
      showShortenForm = true;
    }
  });

  // Function to handle form submission (frontend only)
  function handleShorten() {
    // In a real application, you would send the longUrl and options
    // to the server to get the shortened URL.
    console.log("Shortening URL:", longUrl);
    console.log("Password Enabled:", passwordEnabled);
    console.log("Captcha Forced:", captchaForced);

    let flags = Flags.None;
    if (passwordEnabled) {
      flags |= Flags.Password;
    }
    if (captchaForced) {
      flags |= Flags.Captcha;
    }

    // For now, just simulate showing a shortened URL
    urlInfo = {
      shortUrl: "simulated_short_url",
      Flags: flags,
    };
    showShortenForm = false;
  }

  // Function to handle password input change
  function handlePasswordInput() {
    // This function can be used to react to password changes if needed
    console.log("Password entered:", passwordInput);
  }

  // Function to handle "Proceed after scan" button click (frontend only)
  function handleScanProceed() {
    console.log("Proceeding after scan for URL:", urlInfo?.shortUrl);
    // In a real app, trigger a scan and then redirect
  }

  // Function to handle "Proceed without scan" button click (frontend only)
  function handleNoScanProceed() {
    console.log("Proceeding without scan for URL:", urlInfo?.shortUrl);
    // In a real app, redirect directly
  }

  // Reactively show/hide password input based on checkbox
  $: showPasswordInput = urlInfo?.Flags
    ? (urlInfo.Flags & Flags.Password) > 0
    : false;
</script>

<h1>SecURL: Secure URL Shortener that respects user's privacy</h1>

{#if showShortenForm}
  <div>
    <h2>Shorten your URL</h2>
    <form on:submit|preventDefault={handleShorten}>
      <div>
        <label for="longUrl">Long URL:</label>
        <input type="url" id="longUrl" bind:value={longUrl} required />
        <p class="note">Maximum URL length is 4096 bytes.</p>
      </div>
      <div>
        <h3>Shortening Options</h3>
        <label>
          <input type="checkbox" bind:checked={passwordEnabled} /> Password Protection
        </label>
        <br />
        <label>
          <input type="checkbox" bind:checked={captchaForced} /> Force Captcha
        </label>
      </div>

      {#if showPasswordInput}
        <div>
          <label for="password">Password:</label>
          <input
            type="password"
            id="password"
            bind:value={passwordInput}
            autocomplete="off"
            data-1p-ignore
          />
          <!-- data-1p-ignore is for 1Password, other password managers might need different attributes -->
        </div>
      {/if}

      <button type="submit">Shorten</button>
    </form>
  </div>
{:else if urlInfo}
  <div>
    <h2>Shortened URL Information</h2>
    <p class="disclaimer">
      Disclaimer: We do not guarantee the trustworthiness of the URL.
    </p>
    <div>
      <label for="shortenedUrlDisplay">Shortened URL:</label>
      <input
        type="text"
        id="shortenedUrlDisplay"
        value={urlInfo.shortUrl}
        readonly
      />
    </div>

    {#if urlInfo.Flags && urlInfo.Flags & Flags.Password && !showPasswordInput}
      <div>
        <label for="password">Enter Password to Proceed:</label>
        <input
          type="password"
          id="password"
          bind:value={passwordInput}
          autocomplete="off"
          data-1p-ignore
        />
        <button on:click={() => console.log("Verify password")}>Verify</button>
      </div>
    {:else if urlInfo.Flags && urlInfo.Flags & Flags.Captcha}
      <div>
        <p>Captcha verification required to proceed.</p>
        <!-- Captcha implementation would go here -->
      </div>
    {:else}
      <div class="button-container">
        <button class="scan-button" on:click={handleScanProceed}>
          Proceed after scan
          <span class="scan-note"
            >Scan process may send the URL hash through one or more external
            servers.</span
          >
        </button>
        <button class="no-scan-button" on:click={handleNoScanProceed}>
          Proceed without scan
        </button>
      </div>
    {/if}
  </div>
{:else}
  <div>
    <h2>Error</h2>
    <p>Could not retrieve information for the shortened URL.</p>
  </div>
{/if}

<footer>
  <p>
    GitHub: <a href="https://github.com/gosuda/securl"
      >https://github.com/gosuda/securl</a
    >
  </p>
</footer>

<style>
  h1 {
    font-size: 1.8em; /* Reduced title size */
    color: #5e9cd3; /* Dark mode title color */
    margin-top: 0;
  }

  h2,
  h3 {
    color: #5e9cd3; /* Dark mode heading color */
  }

  div {
    background-color: #1e1e1e; /* Darker div background */
    padding: 1.5em;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.5); /* Stronger dark mode shadow */
    margin-bottom: 1.5em;
  }

  form div,
  .button-container div {
    margin-bottom: 1em;
    background-color: transparent;
    padding: 0;
    box-shadow: none;
  }

  label {
    display: block;
    margin-bottom: 0.5em;
    font-weight: bold;
  }

  input[type="url"],
  input[type="text"],
  input[type="password"] {
    width: calc(100% - 1em);
    padding: 0.5em;
    margin-bottom: 0.5em;
    background-color: #2d2d2d; /* Darker input background */
    color: #e0e0e0; /* Lighter input text color */
    border: 1px solid #444; /* Darker input border */
    border-radius: 4px;
  }

  input[type="checkbox"] {
    margin-right: 0.5em;
  }

  button {
    color: white;
    padding: 0.5em 1em;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.9em;
    transition: background-color 0.3s ease;
  }

  button:hover {
    opacity: 0.9;
  }

  .button-container {
    display: flex;
    flex-direction: column;
    gap: 1em;
  }

  .button-container button {
    width: 100%;
    text-align: center;
  }

  .scan-button {
    background-color: #28a745; /* Green color */
  }

  .no-scan-button {
    background-color: #dc3545; /* Red color */
    padding: 0.4em 1em;
    font-size: 0.8em;
  }

  .scan-note {
    display: block;
    font-size: 0.7em;
    color: rgba(
      255,
      255,
      255,
      0.7
    ); /* Lighter color for the note on dark background */
    margin-top: 0.2em;
  }

  .note,
  .disclaimer {
    font-size: 0.9em;
    color: #bdbdbd; /* Lighter note/disclaimer color */
    margin-top: 0.5em;
  }

  .disclaimer {
    font-weight: bold;
    color: #e57373; /* Dark mode disclaimer color */
  }

  input[readonly] {
    background-color: #3c3c3c; /* Darker readonly background */
    color: #e0e0e0; /* Ensure readonly text is visible */
    cursor: text;
  }
</style>
