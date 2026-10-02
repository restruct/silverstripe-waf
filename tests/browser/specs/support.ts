import { test as base, expect, type Locator, type Page, type Request } from '@playwright/test';

// Shared fixtures and helpers for the WAF admin specs.
//
// The screen is the module's own WafAdmin (/admin/waf). The fixture (tests/browser/fixtures/
// WafBSeed.php, copied into the scratch host by the runner) logs one blocked request on every
// dev/build and lifts the bans and privileged entries these specs create, so each run starts clean.
// The browser connects from 127.0.0.1, which the module whitelists by default, so the WAF itself
// never blocks these specs.

/**
 * test, extended with an automatic console guard: every spec fails if the page logs a console
 * error or throws an uncaught exception at any point, page load included ("Failed to load
 * resource" for any 4xx/5xx counts too).
 */
export const test = base.extend<{ consoleGuard: void }>({
    consoleGuard: [
        async ({ page }, use, testInfo) => {
            const errors: string[] = [];
            page.on('console', (msg) => {
                if (msg.type() === 'error') {
                    errors.push(`console.error: ${msg.text()} (${msg.location().url})`);
                }
            });
            page.on('pageerror', (err) => errors.push(`uncaught: ${err.message}`));

            await use();

            if (errors.length) {
                await testInfo.attach('console-errors', { body: errors.join('\n'), contentType: 'text/plain' });
            }
            expect(errors, 'no console errors or uncaught exceptions').toEqual([]);
        },
        { auto: true },
    ],
});

export { expect };

/** Open the WAF admin on one of its tabs (the jQuery UI tab strip in the panel header). */
export async function openTab(page: Page, tab: 'Blocked Requests' | 'Banned IPs' | 'Privileged IPs' | 'IP Blocklist'): Promise<void> {
    await page.goto('/admin/waf');
    await page.getByRole('tab', { name: tab, exact: true }).click();
}

/** The Active Bans grid on the Banned IPs tab. */
export function bansGrid(page: Page): Locator {
    return page.locator('#Form_EditForm_BannedIPs');
}

/** The row of an IP in the Active Bans grid. */
export function banRow(page: Page, ip: string): Locator {
    // The IP Address cell holds the address alone; match it exactly so 203.0.113.7 is not 203.0.113.70.
    const exact = new RegExp(`^\\s*${ip.replace(/[.:]/g, '\\$&')}\\s*$`);
    return bansGrid(page).locator('tr.ss-gridfield-item').filter({ has: page.locator('td', { hasText: exact }) });
}

/**
 * Wait for a GridField action POST (the grid's own URL, carrying action_gridFieldAlterAction) and
 * assert it is an AJAX request answered with 200. Returns the request.
 */
export async function gridAction(page: Page, grid: string, act: () => Promise<void>): Promise<Request> {
    const url = new RegExp(`/field/${grid}(\\?|$)`);
    const posted = page.waitForRequest((r) => r.method() === 'POST' && url.test(r.url()) && (r.postData() ?? '').includes('action_gridFieldAlterAction'));
    await act();
    const request = await posted;
    expect(['xhr', 'fetch'], 'the grid action is an AJAX request').toContain(request.resourceType());
    expect((await request.response())?.status(), 'grid action status').toBe(200);
    return request;
}

/** Fill in and submit the Manual Ban form under the Active Bans grid. */
export async function manualBan(page: Page, ip: string, hours: string, reason: string): Promise<Request> {
    const form = bansGrid(page).locator('.waf-manual-ban');
    await form.locator('input[type="text"]').first().fill(ip);
    await form.locator('input[type="number"]').fill(hours);
    await form.locator('input[type="text"]').nth(1).fill(reason);
    return gridAction(page, 'BannedIPs', () => form.locator('button.waf-ban').click());
}
