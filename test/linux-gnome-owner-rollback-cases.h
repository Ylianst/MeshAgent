/* SPDX-License-Identifier: Apache-2.0 */
static void owner_rollback_cases(int parent, const mesh_gnome_asset a[3], const mesh_gnome_asset b[3])
{
 int changed = 0, privateDir;
 char backup[MESH_GNOME_ASSET_BACKUP_SIZE], other[MESH_GNOME_ASSET_BACKUP_SIZE];
 char ownerA[65],ownerB[65],ownerC[65];
 memset(ownerA,'a',64);ownerA[64]=0;memset(ownerB,'b',64);ownerB[64]=0;memset(ownerC,'c',64);ownerC[64]=0;
 const char *ownedFiles[]={"metadata.json","protocol.js","extension.js","meshagent-owned.txt"};
 check(mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)==1,"start interleaved registration fixture");
 check(mesh_gnome_assets_acquire(parent,a,ownerB,1,backup,&changed)==1&&changed,"begin service B registration");strcpy(other,backup);
 check(mesh_gnome_assets_acquire(parent,a,ownerC,1,backup,&changed)==1&&changed,"service C registers after B transaction");
 check(!mesh_gnome_assets_rollback(parent,other),"stale registration rollback cannot erase later service");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit later registration backup");
 check(mesh_gnome_assets_commit(parent,other)==1,"discard stale registration backup without touching current");
 check(mesh_gnome_assets_release(parent,ownerC,backup,&changed)==1&&changed,"later service ownership survived rejected rollback");
 if(changed){check(mesh_gnome_assets_rollback(parent,backup)==1,"restore observed C owner");check(mesh_gnome_assets_commit(parent,backup)==1,"discard C observation candidate");}
 const char *interleavedOwners[]={ownerA,ownerB,ownerC};
 for(size_t oi=0;oi<3;++oi){check(mesh_gnome_assets_release(parent,interleavedOwners[oi],backup,&changed)==1,"clean interleaved owner");if(backup[0])check(mesh_gnome_assets_commit(parent,backup)==1,"commit interleaved cleanup");}
 check(mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)==1,"start interleaved final removal");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&changed,"detach final owner before another service installs");strcpy(other,backup);
 check(mesh_gnome_assets_acquire(parent,b,ownerB,1,backup,&changed)==1&&changed,"new service installs while old removal pending");
 check(!mesh_gnome_assets_rollback(parent,other),"stale uninstall rollback cannot replace new service installation");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-b"),"new service payload survives rejected uninstall rollback");
 check(mesh_gnome_assets_commit(parent,other)==1,"clean detached old installation only");
 for(size_t oi=0;oi<2;++oi){check(mesh_gnome_assets_release(parent,interleavedOwners[oi],backup,&changed)==1,"clean uninstall interleaving fixture");if(backup[0])check(mesh_gnome_assets_commit(parent,backup)==1,"commit uninstall interleaving cleanup");}
 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1,"start legacy rollback guard fixture");
 check(mesh_gnome_assets_install(parent,b,backup,&changed)==1&&changed,"legacy update creates unbound rollback token");strcpy(other,backup);
 check(mesh_gnome_assets_acquire(parent,b,ownerA,1,backup,&changed)==1&&changed,"service ownership appears after legacy update");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit legacy adoption before stale rollback");
 check(!mesh_gnome_assets_rollback(parent,other),"legacy rollback cannot erase new service ownership");
 check(mesh_gnome_assets_commit(parent,other)==1,"discard stale legacy backup");
 privateDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(privateDir<0)exit(2);
 for(size_t oi=0;oi<4;++oi)if(unlinkat(privateDir,ownedFiles[oi],0))exit(2);
 close(privateDir);if(unlinkat(parent,MESH_GNOME_ASSET_UUID,AT_REMOVEDIR))exit(2);
}
