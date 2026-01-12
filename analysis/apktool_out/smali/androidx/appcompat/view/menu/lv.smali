.class public final Landroidx/appcompat/view/menu/lv;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Landroidx/appcompat/view/menu/qv;

.field public final b:Ljava/util/concurrent/CopyOnWriteArrayList;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/qv;)V
    .locals 1

    const-string v0, "fragmentManager"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/lv;->a(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p3, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final b(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 0

    const-string p2, "f"

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/qv;->j0()Landroidx/appcompat/view/menu/jv;

    const/4 p1, 0x0

    throw p1
.end method

.method public final c(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/lv;->c(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p3, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final d(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/lv;->d(Landroidx/appcompat/view/menu/ev;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final e(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/lv;->e(Landroidx/appcompat/view/menu/ev;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final f(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 0

    const-string p2, "f"

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/qv;->j0()Landroidx/appcompat/view/menu/jv;

    const/4 p1, 0x0

    throw p1
.end method

.method public final g(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/lv;->g(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p3, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final h(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/lv;->h(Landroidx/appcompat/view/menu/ev;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final i(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "outState"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/lv;->i(Landroidx/appcompat/view/menu/ev;Landroid/os/Bundle;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p3, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final j(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/lv;->j(Landroidx/appcompat/view/menu/ev;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final k(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/lv;->k(Landroidx/appcompat/view/menu/ev;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final l(Landroidx/appcompat/view/menu/ev;Landroid/view/View;Landroid/os/Bundle;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "v"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/lv;->l(Landroidx/appcompat/view/menu/ev;Landroid/view/View;Landroid/os/Bundle;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p4, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method

.method public final m(Landroidx/appcompat/view/menu/ev;Z)V
    .locals 2

    const-string v0, "f"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/lv;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->l0()Landroidx/appcompat/view/menu/ev;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->C()Landroidx/appcompat/view/menu/qv;

    move-result-object v0

    const-string v1, "parent.getParentFragmentManager()"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/qv;->k0()Landroidx/appcompat/view/menu/lv;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/lv;->m(Landroidx/appcompat/view/menu/ev;Z)V

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lv;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_1

    throw p1

    :cond_1
    throw p1

    :cond_2
    return-void
.end method
