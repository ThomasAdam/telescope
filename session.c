/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "defaults.h"
#include "fs.h"
#include "minibuffer.h"
#include "parser.h"
#include "session.h"
#include "ui.h"

static struct event	 autosaveev;

void
switch_to_tab(struct tab *tab)
{
	current_tab = tab;
	tab->flags &= ~TAB_URGENT;

	if (operating && tab->flags & TAB_LAZY)
		load_url_in_tab(tab, tab->hist_cur->h, NULL, 0);
}

unsigned int
tab_new_id(void)
{
	static uint32_t tab_counter;

	return tab_counter++;
}

struct tab *
new_tab(const char *url, const char *base, struct tab *after)
{
	struct tab	*tab;

	ui_schedule_redraw();
	autosave_hook();

	if ((tab = calloc(1, sizeof(*tab))) == NULL) {
		event_loopbreak();
		return NULL;
	}

	TAILQ_INIT(&tab->hist.head);

	TAILQ_INIT(&tab->buffer.head);
	TAILQ_INIT(&tab->buffer.page.head);

	tab->id = tab_new_id();
	if (!operating)
		tab->flags |= TAB_LAZY;
	switch_to_tab(tab);

	if (after != NULL)
		TAILQ_INSERT_AFTER(&tabshead, after, tab, tabs);
	else
		TAILQ_INSERT_TAIL(&tabshead, tab, tabs);

	load_url_in_tab(tab, url, base, 0);
	return tab;
}

/*
 * Free every resource linked to the tab, including the tab itself.
 * Removes the tab from the tablist, but doesn't update the
 * current_tab though.
 */
void
free_tab(struct tab *tab)
{
	stop_tab(tab);
	ui_schedule_redraw();
	autosave_hook();

	if (evtimer_pending(&tab->loadingev, NULL))
		evtimer_del(&tab->loadingev);

	TAILQ_REMOVE(&tabshead, tab, tabs);
	free(tab);
}

void
stop_tab(struct tab *tab)
{
	ui_send_net(IMSG_STOP, tab->id, NULL, 0);
}

void
save_session(void)
{
	struct session_tab	 st;
	struct tab		*tab;

	if (safe_mode)
		return;

	ui_send_fs(IMSG_SESSION_START, 0, NULL, 0);

	TAILQ_FOREACH(tab, &tabshead, tabs) {
		memset(&st, 0, sizeof(st));

		if (tab == current_tab)
			st.flags = TAB_CURRENT;

		strlcpy(st.uri, tab->hist_cur->h, sizeof(st.uri));
		strlcpy(st.title, tab->buffer.page.title, sizeof(st.title));
		ui_send_fs(IMSG_SESSION_TAB, 0, &st, sizeof(st));
	}

	ui_send_fs(IMSG_SESSION_END, 0, NULL, 0);
}

void
autosave_init(void)
{
	evtimer_set(&autosaveev, autosave_timer, NULL);
}

void
autosave_timer(int fd, short event, void *data)
{
	save_session();
}

/*
 * Function to be called in "interesting" places where we may want to
 * schedule an autosave (like on new tab or before loading an url.)
 */
void
autosave_hook(void)
{
	struct timeval tv;

	if (autosave <= 0)
		return;

	if (!evtimer_pending(&autosaveev, NULL)) {
		tv.tv_sec = autosave;
		tv.tv_usec = 0;

		evtimer_add(&autosaveev, &tv);
	}
}
