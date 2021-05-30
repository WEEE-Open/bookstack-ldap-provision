<?php /** @noinspection PhpMultipleClassesDeclarationsInOneFile */

namespace BookStack\Console\Commands;

use BookStack\Auth\Access\Ldap;
use BookStack\Auth\Permissions\RolePermission;
use BookStack\Auth\Role;
use BookStack\Auth\User;
use Illuminate\Console\Command;
use BookStack\Auth\Access\LdapService;
use Illuminate\Support\Facades\Log;

class LdapProvisionService extends LdapService
{
    public function getUsersForProvisioning(string $baseDn, string $usersFilter, array $attributes)
    {
        $ldapConnection = $this->getConnection();
        $this->bindSystemUser($ldapConnection);

        $followReferrals = $this->config['follow_referrals'] ? 1 : 0;
        $this->ldap->setOption($ldapConnection, LDAP_OPT_REFERRALS, $followReferrals);

        $users = $this->ldap->searchAndGetEntries($ldapConnection, $baseDn, $usersFilter, $attributes);

        return $users;
    }

    public function getGroupsForProvisioning(string $groupsBaseDn, string $groupsFilter, array $attributes)
    {
        $ldapConnection = $this->getConnection();
        $this->bindSystemUser($ldapConnection);

        $followReferrals = $this->config['follow_referrals'] ? 1 : 0;
        $this->ldap->setOption($ldapConnection, LDAP_OPT_REFERRALS, $followReferrals);

        $groups = $this->ldap->searchAndGetEntries($ldapConnection, $groupsBaseDn, $groupsFilter, $attributes);

        return $groups;
    }
}

class LdapProvision extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'bookstack:ldap-provision';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Provision accounts and groups from LDAP';

    protected $ldap;
    protected $config;

    protected $externalIdAttr;
    protected $emailAttr;
    protected $nameAttr;

    protected $groupsExternalIdAttr;
    protected $groupsNameAttr;
    protected $groupsDescriptionAttr;

    protected $allowDisasters;
    protected $softDelete;
    protected $createEmptyGroups;

    protected $adminGroupName;

    protected const NO_PASSWORD_DELETED = 'no password (deleted)';

    /**
     * Create a new command instance.
     */
    public function __construct()
    {
        parent::__construct();

        $this->config = config('services.ldap');
        $this->ldap = new LdapProvisionService(new Ldap());

        $this->externalIdAttr = strtolower(env('LDAP_PROVISION_EXTERNAL_ID_ATTR'))
            ?? dd('LDAP_PROVISION_EXTERNAL_ID_ATTR not set');
        $this->emailAttr = strtolower(env('LDAP_PROVISION_EMAIL_ATTR'))
            ?? dd('LDAP_PROVISION_EMAIL_ATTR not set');
        $this->nameAttr = strtolower(env('LDAP_PROVISION_NAME_ATTR'))
            ?? dd('LDAP_PROVISION_NAME_ATTR not set');

        $this->groupsExternalIdAttr = strtolower(env('LDAP_PROVISION_GROUPS_EXTERNAL_ID_ATTR', $this->externalIdAttr));
        $this->groupsNameAttr = strtolower(env('LDAP_PROVISION_GROUPS_NAME_ATTR', $this->nameAttr));
        if (env('LDAP_PROVISION_GROUPS_DESCRIPTION_ATTR') === null) {
            $this->groupsDescriptionAttr = null;
        } else {
            $this->groupsDescriptionAttr = strtolower(env('LDAP_PROVISION_GROUPS_DESCRIPTION_ATTR'));
        }
        $this->adminGroupName = env('LDAP_PROVISION_ADMIN_GROUP_NAME');

        $this->allowDisasters = ! boolval(env('LDAP_PROVISION_ALLOW_DISASTERS', true));
        $this->softDelete = boolval(env('LDAP_PROVISION_SOFT_DELETE', true));
        $this->createEmptyGroups = boolval(env('LDAP_PROVISION_CREATE_EMPTY_GROUPS', true));
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $usersBaseDn = env(
            'LDAP_PROVISION_USERS_BASE_DN',
            $this->config['base_dn']
        ) ?? dd('LDAP_PROVISION_USERS_BASE_DN not set');

        $usersFilter = env(
            'LDAP_PROVISION_USERS_FILTER',
            $this->config['user_filter']
        ) ?? dd('LDAP_PROVISION_USERS_FILTER not set');

        $groupsBaseDn = env('LDAP_PROVISION_GROUPS_BASE_DN')
            ?? dd('LDAP_PROVISION_GROUPS_BASE_DN not set');

        $groupsFilter = env('LDAP_PROVISION_GROUPS_FILTER')
            ?? dd('LDAP_PROVISION_GROUPS_FILTER not set');


        $excludedUsers = env('LDAP_PROVISION_EXCLUDE_USERS', []);

        if (empty($excludedUsers)) {
            $excludedUsersAttr = null;
        } else {
            $excludedUsers = array_reverse($excludedUsers);
            $excludedUsersAttr = array_pop($excludedUsers);
        }

        $requiredUserAttributes = [
            'dn',
            $this->externalIdAttr,
            $this->emailAttr,
            $this->nameAttr,
        ];

        // Get data from LDAP
        $users = $this->ldap->getUsersForProvisioning($usersBaseDn, $usersFilter, $requiredUserAttributes);
        $groups = $this->ldap->getGroupsForProvisioning($groupsBaseDn, $groupsFilter, ['member', $this->groupsExternalIdAttr, $this->groupsNameAttr, $this->groupsDescriptionAttr]);

        // Add users
        $users = $this->filterUsers($users, $requiredUserAttributes, $excludedUsersAttr, $excludedUsers);
        $dnToUser = $this->parseUsers($users);

        // Add groups
        $dnToGroup = $this->parseGroups($groups, $dnToUser);

        // Remove deleted users
        if ($this->allowDisasters || count($dnToUser) > 0) {
            $this->deleteUsers($dnToUser);
        }

        // Remove deleted Groups
        if ($this->allowDisasters || count($dnToGroup) > 0) {
            $this->deleteGroups($dnToGroup);
        }

        // Set permissions
        if (isset($this->adminGroupName) && strlen($this->adminGroupName) > 0) {
            $this->setAdminPermissions($dnToGroup);
        }
    }

    protected function filterUsers(array $users, array $requiredAttributes, string $excludedMatchAttribute = null, array $excludedUsersAttributes = []): array
    {
        $result = [];
        foreach ($users as $user) {
            if ($excludedMatchAttribute != null) {
                if (isset($user[$excludedMatchAttribute]) && isset($excludedUsersAttributes[$user[$excludedMatchAttribute]])) {
                    continue;
                }
            }
            $complete = true;
            foreach ($requiredAttributes as $attr) {
                if (!isset($user[$attr])) {
                    $complete = false;
                    break;
                }
            }
            if ($complete) {
                $result[] = $user;
            }
        }
        return $result;
    }

    private function parseGroups(array $groups, array $dnToUser): array
    {
        $allRoles = [];
        $userDnToGroupId = [];
        foreach ($groups as $group) {
            if (isset($group[$this->groupsExternalIdAttr][0]) && isset($group[$this->groupsNameAttr][0])) {
                $name = $group[$this->groupsNameAttr][0];
                //$name = str_replace(' ', '-', trim(strtolower($name)));
                // syncWithGroups does the same replacement
                $external_id = str_replace(' ', '-', trim(strtolower($group[$this->groupsExternalIdAttr][0])));
                $description = $group[$this->groupsDescriptionAttr][0] ?? "$name group from LDAP";

                if (isset($group['member'])) {
                    if (!$this->createEmptyGroups && $group['member']['count'] <= 0) {
                        continue;
                    }
                    foreach ($group['member'] as $key => $memberDn) {
                        if ($key !== 'count') {
                            $userDnToGroupId[$memberDn][] = $external_id;
                        }
                    }
                }

                $role = Role::where('external_auth_id', '=', $external_id)->first();

                if ($role === null) {
                    // Role doesn't exist
                    $role = new Role();

                    $role->display_name = $name;
                    $role->description = $description;
                    $role->external_auth_id = $external_id;
                    //$role->system_name = ''; // not null

                    $role->save();
                } else {
                    $changed = false;
                    if ($role->display_name !== $name) {
                        $role->display_name = $name;
                        $changed = true;
                    }
                    if ($role->description !== $description) {
                        $role->description = $description;
                        $changed = true;
                    }
                    if ($changed) {
                        $role->save();
                    }
                }
                $allRoles[$external_id] = $role;
            }
        }

        foreach ($userDnToGroupId as $dn => $groupIds) {
            $user = $dnToUser[$dn] ?? null;
            if ($user !== null) {
                $this->ldap->syncWithGroups($user, $groupIds);
            }
        }

        return $allRoles;
    }

    protected function parseUsers(array $users): array
    {
        $dnToUser = [];
        foreach ($users as $ldapUser) {
            /** @var User|null $user */
            $user = User::where('external_auth_id', '=', $ldapUser[$this->externalIdAttr][0])->first();
            if ($user === null) {
                // user doesn't exist
                $userByMail = User::where('email', '=', $ldapUser[$this->emailAttr][0])->first();
                if ($userByMail !== null) {
                    Log::warning("[LDAP provisioning] user ID {$ldapUser[$this->externalIdAttr][0]} does not match any account but email is the same as user {$userByMail->id}, skipping");
                    continue;
                }

                $user = new User();

                $user->name = $ldapUser[$this->nameAttr][0];
                $user->email = $ldapUser[$this->emailAttr][0];
                $user->password = 'no password';
                $user->email_confirmed = true;
                $user->external_auth_id = $ldapUser[$this->externalIdAttr][0];

                $user->refreshSlug();
                $user->save();
            } else {
                $changed = false;
                if ($user->name !== $ldapUser[$this->nameAttr][0]) {
                    $user->name = $ldapUser[$this->nameAttr][0];
                    $changed = true;
                }
                if ($user->email !== $ldapUser[$this->emailAttr][0]) {
                    $user->email = $ldapUser[$this->emailAttr][0];
                    $changed = true;
                }
                if ($user->password !== 'no password') {
                    $user->password = 'no password';
                    $changed = true;
                }
                if ($user->email_confirmed) {
                    $user->email_confirmed = true;
                    $changed = true;
                }
                if ($changed) {
                    $user->refreshSlug();
                    $user->save();
                }
            }
            $dnToUser[$ldapUser['dn']] = $user;
        }
        return $dnToUser;
    }

    protected function deleteUsers(array $externalIds): void
    {
        $allUsers = User::whereNotNull('external_auth_id')->get();
        $i = 0;
        foreach ($allUsers as $user) {
            /** @var User $user */
            if (strlen($user->external_auth_id) <= 0) {
                continue;
            }

            if (!isset($externalIds[$user->external_auth_id])) {
                // TODO: what happens to owned books?
                if ($this->softDelete) {
                    // Do not delete twice
                    if ($user->password == self::NO_PASSWORD_DELETED) {
                        continue;
                    }

                    //$deleted_id = substr(sha1($user->external_auth_id), 0, 10) . time() . $i++;
                    $deleted_id = substr(sha1((string) mt_rand()), 0, 10) . time() . $i++;
                    $user->name = "Deleted $deleted_id";
                    $user->password = self::NO_PASSWORD_DELETED;
                    $user->email_confirmed = false;
                    $user->email = $deleted_id . '@deleted.invalid';
                    $user->email_confirmed = false;
                    $user->refreshSlug();
                    $user->save();
                } else {
                    $user->delete();
                }
            }
        }
    }

    protected function deleteGroups(array $externalIds): void
    {
        $allGroups = Role::whereNotNull('external_auth_id')->get();
        foreach ($allGroups as $group) {
            /** @var Role $group */
            if (strlen($group->external_auth_id) <= 0) {
                continue;
            }

            if (!isset($externalIds[$group->external_auth_id])) {
                $group->delete();
            }
        }
    }

    protected function setAdminPermissions(array $dnToGroup)
    {
        foreach ($dnToGroup as $group) {
            /** @var Role $group */
            if ($group->display_name === $this->adminGroupName) {
                $permissions = ['settings-manage', 'users-manage', 'user-roles-manage'];
                $ids = RolePermission::whereIn('name', $permissions)->pluck('id');
                foreach ($ids as $id) {
                    $group->permissions()->syncWithoutDetaching($id);
                }
                break;
            }
        }
    }
}
