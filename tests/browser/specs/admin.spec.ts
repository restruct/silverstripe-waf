import { test, expect, openTab } from './support';

// The WAF admin screen itself: its tabs, the status block, the blocked-request log and the
// privileged IPs (a DataObject with its own validation, which runs through a different extension
// hook on Silverstripe 5 and 6).

test('the admin shows its four tabs, the status block and the logged blocked request', async ({ page }) => {
    await page.goto('/admin/waf');
    await expect(page.getByRole('tab')).toHaveText(['Blocked Requests', 'Banned IPs', 'Privileged IPs', 'IP Blocklist']);
    const panel = page.locator('#Root_BlockedRequests');
    await expect(panel).toContainText('WAF Status');
    await expect(panel).toContainText('Storage Mode: file');

    // The entry the fixture logs on every dev/build.
    const row = page.locator('#Form_EditForm_BlockedRequests tr.ss-gridfield-item').filter({ hasText: 'browser-fixture' }).first();
    await expect(row).toBeVisible();
    await expect(row).toContainText('192.0.2.44');
    await expect(row).toContainText('bad_user_agent');
    await expect(row).toContainText('/wp-login.php?browser-fixture=1');
    await expect(row).toContainText('sqlmap/1.7 (browser fixture)');

    await page.getByRole('tab', { name: 'IP Blocklist', exact: true }).click();
    await expect(page.locator('#Root_Blocklist')).toBeVisible();
});

test.describe('Privileged IPs', () => {
    async function addPrivileged(page: import('@playwright/test').Page, ip: string, factor: string) {
        await openTab(page, 'Privileged IPs');
        await page.locator('#Form_EditForm_PrivilegedIPs .grid-field__toolbar a, #Form_EditForm_PrivilegedIPs a.action_gridfield_add, #Form_EditForm_PrivilegedIPs .btn-primary').filter({ hasText: /Add/ }).first().click();
        await expect(page.locator('#Form_ItemEditForm_IpAddress')).toBeVisible();
        await page.locator('#Form_ItemEditForm_IpAddress').fill(ip);
        await page.locator('#Form_ItemEditForm_Factor').fill(factor);
        const posted = page.waitForResponse((r) => r.request().method() === 'POST' && /\/ItemEditForm(\?|$)/.test(r.url()));
        await page.locator('#Form_ItemEditForm button[name="action_doSave"]').click();
        return posted;
    }

    test('a CIDR range with a factor is saved and listed', async ({ page }) => {
        // Counted against a snapshot: under --repeat-each earlier repeats have added the same range.
        const rows = page.locator('#Form_EditForm_PrivilegedIPs tr.ss-gridfield-item', { hasText: '198.51.100.0/24' });
        await openTab(page, 'Privileged IPs');
        const before = await rows.count();
        const response = await addPrivileged(page, '198.51.100.0/24', '3');
        expect(response.status()).toBe(200);
        await expect(page.locator('#Form_ItemEditForm .message.good, .toast, .notice-item').first()).toBeVisible();

        await openTab(page, 'Privileged IPs');
        await expect(rows).toHaveCount(before + 1);
    });

    test('an invalid address is refused by the model\'s validation', async ({ page }) => {
        await addPrivileged(page, 'not-an-ip', '0');
        // Field messages from PrivilegedIp::validateIpAndFactor(), via updateValidate (SS6) or
        // validate (SS5): before 1.6.0 the SS6 hook was missing and every record validated.
        await expect(page.locator('#Form_ItemEditForm')).toContainText('Invalid IP address');
        await expect(page.locator('#Form_ItemEditForm')).toContainText('Factor must be greater than 0');

        await openTab(page, 'Privileged IPs');
        await expect(page.locator('#Form_EditForm_PrivilegedIPs tr.ss-gridfield-item', { hasText: 'not-an-ip' })).toHaveCount(0);
    });
});
