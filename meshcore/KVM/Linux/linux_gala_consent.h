/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_GALA_CONSENT_H
#define MESH_GALA_CONSENT_H
/* Installer only: 0=requested, 2=declined, 3=deferred. No connection path calls it. */
int mesh_gala_offer_signout(void);
#endif
