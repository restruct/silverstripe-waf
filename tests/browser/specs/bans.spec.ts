import { test, expect, banRow, bansGrid, gridAction, manualBan, openTab } from './support';

// Manual ban and unban on the WAF admin's Banned IPs tab (GridFieldManualBan, GridFieldUnbanAction):
// both are GridField actions, posted with the form's security token through the CMS's own AJAX
// request, and the grid re-renders in place.

test('a manual ban is listed with its reason and survives a reload', async ({ page }) => {
    await openTab(page, 'Banned IPs');
    await expect(banRow(page, '203.0.113.7')).toHaveCount(0);

    const request = await manualBan(page, '203.0.113.7', '2', 'Browser spec ban');
    // GridField actions carry the form's SecurityID (checked before the action runs).
    expect(request.postData() ?? '').toMatch(/SecurityID=[0-9a-f]+/);

    const row = banRow(page, '203.0.113.7');
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('Browser spec ban');
    await expect(row.locator('button.waf-unban')).toHaveAttribute('title', 'Unban 203.0.113.7');

    await openTab(page, 'Banned IPs');
    await expect(banRow(page, '203.0.113.7')).toHaveCount(1);

    // Lift it again, so a repeat run (--repeat-each) starts without it.
    await gridAction(page, 'BannedIPs', () => banRow(page, '203.0.113.7').locator('button.waf-unban').click());
});

test('"Unban" lifts the ban and the row disappears', async ({ page }) => {
    await openTab(page, 'Banned IPs');
    await manualBan(page, '203.0.113.8', '1', 'To be lifted');
    const row = banRow(page, '203.0.113.8');
    await expect(row).toHaveCount(1);

    await gridAction(page, 'BannedIPs', () => row.locator('button.waf-unban').click());
    await expect(banRow(page, '203.0.113.8')).toHaveCount(0);

    await openTab(page, 'Banned IPs');
    await expect(banRow(page, '203.0.113.8')).toHaveCount(0);
});

test('an invalid address is refused with a message and nothing is banned', async ({ page }) => {
    await openTab(page, 'Banned IPs');
    const before = await bansGrid(page).locator('tr.ss-gridfield-item').count();
    // The pattern attribute would stop the browser from submitting "10.0.0.0/8"-style ranges only
    // on a real form submit; the GridField action posts anyway, so the server must refuse it.
    await manualBan(page, '10.0.0.999', '1', 'Invalid');
    await expect(bansGrid(page)).toContainText("Not banned: '10.0.0.999' is not a valid IPv4 or IPv6 address.");
    await expect(bansGrid(page).locator('tr.ss-gridfield-item')).toHaveCount(before);
});

test('an IPv6 ban is stored and listed in canonical form', async ({ page }) => {
    // Bans are keyed on the exact string and PHP reports clients in compressed lower case, so a
    // ban typed in another spelling must be stored as 2001:db8::99 to block anyone.
    await openTab(page, 'Banned IPs');
    await manualBan(page, '2001:0DB8:0:0:0:0:0:99', '1', 'IPv6 spelling');
    await expect(banRow(page, '2001:db8::99')).toHaveCount(1);
    await expect(bansGrid(page)).not.toContainText('2001:0DB8');

    // Lift it again, so a repeat run (--repeat-each) starts without it.
    await gridAction(page, 'BannedIPs', () => banRow(page, '2001:db8::99').locator('button.waf-unban').click());
    await expect(banRow(page, '2001:db8::99')).toHaveCount(0);
});
