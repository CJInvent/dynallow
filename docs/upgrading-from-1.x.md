# Replacing pre-service installations

New installations should follow [Add a site](3-add-a-site.md). This page is only for retiring older deployed clients; old executable scripts are not shipped in this source tree.

For the previous IPF1 agent, preserve identity using the native EXE's `install` command without a profile, or the Docker installer's `--upgrade`. Back up protected data and verify the former processes have stopped. See the [deployment guide](8-native-agents-and-releases.md).

For pre-IPF1 IPUpdater deployments, create a new server site using the existing hostname. Stop and disable the old updater before installing the new client. The native installer removes known old scheduled tasks, but does not promise to remove arbitrary old processes, scripts, or DNS-token files. Identify and remove those files locally after confirming the replacement works, and revoke the old per-machine DNS tokens. Retire the old status server after all sites have migrated.
