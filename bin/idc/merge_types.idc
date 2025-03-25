/*
    Copyright © 2017-2025 AO Kaspersky Lab

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Author: Sergey.Belov at kaspersky.com
*/

/**************************************************************************************************************************
This idc script intended for interactive merging accumulated types (especially structures) across multiple IDBs.
Following workflow is proposed:
0 - copy "merge_types.idc" file to your "ida/idc" folder and "add2merge.sh" to somewhere in PATH (ex: "~/bin", ""~/.local/bin", etc)
1 - after analyzing the first sample save typeinfo into idc file. Main menu: File -> Produce file -> Dump typeinfo to IDC file
2 - before analyzing the second sample import typeinfo from the first one. Main menu: File -> Script file -> select file generated at step 1.
3 - after analyzing second sample do again "File -> Produce file -> Dump typeinfo to IDC file"
-- now if we want to return to the partialy analyzed first sample with updated typeinfo we can't simple repeat step 2, because ida will ignore adding types already exist.
4 - convert our typeinfo idc by running following command "add2merge.sh {typeinfo.idc}" which runs following 'sed' command for a few replacements:
    sed -e 's/SetType/merge_type/g; s/add_struc_member/merge_struc_member/g; s/idc.idc/merge_types.idc/; /^static main(void)$/ { n; /^{$/ { s/{/{ init_merge_types();/; p;d;}};' $1 > m$1
5 - open idb with the fist sample and then immediately run converted idc file obtained at step 4. Answer all appeared dialog boxes, there are may be a low of them, press "Cancel" if brave enough.
6 - repeat steps  2-5 every time when your typeinfo idc is filled with new types or modifications of existing ones
**************************************************************************************************************************/

#include <idc.idc>

extern all;

static init_merge_types()
{
	all = -1;
}

static isBadName(name)
{
	if(name == "")
		return 1;
	if(substr(name, 0, 4) == "fld_")
		return 1;
	if(substr(name, 0, 6) == "field_")
		return 1;
	if(substr(name, 0, 4) == "sub_")
		return 1;
	if(substr(name, 0, 5) == "psub_")
		return 1;
	if(substr(name, 0, 4) == "gap_")
		return 1;
	return 0;
}

static ask_all() {
	auto askall;
	askall = ask_yn(0, "Answer for all remain questions: Yes, No, Cancel - save database and exit from ida?");
	if(askall == -1 )
		qexit(0xBAD);
	all = askall;
	return askall;
}

//static long merge_struc_member(long id, string name, long offset, long flag, long typeid, long nbytes, long target, long tdelta, long reftype)
static merge_struc_member(id, name, offset, flag, typeid, nbytes, target = -1, tdelta = 0, reftype = 0)
{
  auto res;
  auto oldName, oldSz, strucName;
  auto prompt, askres, off, poff;

	if(isOff0(flag))
		res = add_struc_member(id, name, offset, flag, typeid, nbytes, target, tdelta, reftype);
	else
		res = add_struc_member(id, name, offset, flag, typeid, nbytes);
	if(res == 0)
		return 0;
	if(is_union(id))
		return res;

	oldName = get_member_name(id, offset);
	oldSz = get_member_size(id, offset);
	if(oldName == name && oldSz == nbytes)
		return res;

	strucName = get_struc_name(id);
	if(res == STRUC_ERROR_MEMBER_NAME) {
		if(all == -1) {
			prompt = sprintf("name\n'%s.%s'\nalready exist, rename?", strucName, name);
			askres = ask_yn(0, prompt);
			if(askres == -1) {
				askres = ask_all();
			}
		} else {
			askres = all;
		}
		if(askres == 1) {
			off = get_member_offset(id, name);
			prompt = sprintf("%s_%x", name, off);
			if(set_member_name(id, off, prompt))
				return merge_struc_member(id, name, offset, flag, typeid, nbytes, target, tdelta, reftype);
			msg("!set_member_name('%s.%s', 0x%x, '%s') err %d\n", strucName, name, off, prompt);
		}
	} else if(res == STRUC_ERROR_MEMBER_OFFSET) {
		askres = 0;
		if(isBadName(name)) {
			askres = 0;
		} else if(isBadName(oldName)) {
			askres = 1;
		} else {
			if(all == -1) {
				prompt = sprintf("replace\n'%s.%s' (%x)\nto\n%x: '%s' (%x)", strucName, oldName, oldSz, offset,name, nbytes);
				askres = ask_yn(0, prompt);
				if(askres == -1) {
					askres = ask_all();
				}
			} else {
				askres = all;
			}
		}
		if(askres == 1) {
			off = offset;
			while(off < offset + nbytes && off < get_struc_size(id)) {
				poff = off;
				off = get_next_offset(id, poff);
				del_struc_member(id, poff);
				if(off == poff) {
					msg("oops! get_next_offset(%s, 0x%x)\n", strucName, poff);
					break;
				}
			}
			if(isOff0(flag))
				res = add_struc_member(id, name, offset, flag, typeid, nbytes, target, tdelta, reftype);
			else
				res = add_struc_member(id, name, offset, flag, typeid, nbytes);
			if(res == 0)
				return 0;
			msg("--- second ");
		} else if(askres == 0) {
			return res;
		}
	}

	msg("add_struc_member('%s.%s', 0x%x, 0x%x) err %d\n", strucName, name, offset, nbytes, res);
	return res;
}

static merge_type(ea, type)
{
  auto res;
  auto oldType, name;
  auto prompt, askres, askall;
  
	oldType = get_type(ea);
	if(oldType == type)
		return 1;

	name = get_name(ea);
	if(name == "")
		name = sprintf("%a", ea);

	askres = 0;
	if(oldType == "") {
		askres = 1;
	} else {
		if(all == -1) {
			prompt = sprintf("replace type of '%s' from\n%s\nto\n%s", name, oldType, type);
			askres = ask_yn(0, prompt);
			if(askres == -1) {
				askres = ask_all();
			}
		} else {
			askres = all;
		}
	}

	if(askres == 1) {
		res = apply_type(ea, type);
		if(res != 1)
			msg("apply_type(%s, %s) err %d\n", name, type, res);
	}

  return 1;
}
