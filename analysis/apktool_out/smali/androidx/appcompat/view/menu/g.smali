.class public abstract Landroidx/appcompat/view/menu/g;
.super Landroidx/appcompat/view/menu/y60;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/wg;
.implements Landroidx/appcompat/view/menu/sh;


# instance fields
.field public final o:Landroidx/appcompat/view/menu/jh;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/jh;ZZ)V
    .locals 0

    invoke-direct {p0, p3}, Landroidx/appcompat/view/menu/y60;-><init>(Z)V

    if-eqz p2, :cond_0

    sget-object p2, Landroidx/appcompat/view/menu/n60;->d:Landroidx/appcompat/view/menu/n60$b;

    invoke-interface {p1, p2}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p2

    check-cast p2, Landroidx/appcompat/view/menu/n60;

    invoke-virtual {p0, p2}, Landroidx/appcompat/view/menu/y60;->f0(Landroidx/appcompat/view/menu/n60;)V

    :cond_0
    invoke-interface {p1, p0}, Landroidx/appcompat/view/menu/jh;->o(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/g;->o:Landroidx/appcompat/view/menu/jh;

    return-void
.end method


# virtual methods
.method public H0(Ljava/lang/Object;)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/y60;->I(Ljava/lang/Object;)V

    return-void
.end method

.method public I0(Ljava/lang/Throwable;Z)V
    .locals 0

    return-void
.end method

.method public J0(Ljava/lang/Object;)V
    .locals 0

    return-void
.end method

.method public final K0(Landroidx/appcompat/view/menu/wh;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)V
    .locals 0

    invoke-virtual {p1, p3, p2, p0}, Landroidx/appcompat/view/menu/wh;->e(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)V

    return-void
.end method

.method public O()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {p0}, Landroidx/appcompat/view/menu/gj;->a(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " was cancelled"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final b()Landroidx/appcompat/view/menu/jh;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/g;->o:Landroidx/appcompat/view/menu/jh;

    return-object v0
.end method

.method public c()Z
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/y60;->c()Z

    move-result v0

    return v0
.end method

.method public final e0(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/g;->o:Landroidx/appcompat/view/menu/jh;

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/qh;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Throwable;)V

    return-void
.end method

.method public l()Landroidx/appcompat/view/menu/jh;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/g;->o:Landroidx/appcompat/view/menu/jh;

    return-object v0
.end method

.method public m0()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/g;->o:Landroidx/appcompat/view/menu/jh;

    invoke-static {v0}, Landroidx/appcompat/view/menu/kh;->b(Landroidx/appcompat/view/menu/jh;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-super {p0}, Landroidx/appcompat/view/menu/y60;->m0()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const/16 v2, 0x22

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "\":"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-super {p0}, Landroidx/appcompat/view/menu/y60;->m0()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final n(Ljava/lang/Object;)V
    .locals 2

    const/4 v0, 0x0

    const/4 v1, 0x1

    invoke-static {p1, v0, v1, v0}, Landroidx/appcompat/view/menu/qd;->d(Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/y60;->k0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Landroidx/appcompat/view/menu/z60;->b:Landroidx/appcompat/view/menu/iy0;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/g;->H0(Ljava/lang/Object;)V

    return-void
.end method

.method public final r0(Ljava/lang/Object;)V
    .locals 1

    instance-of v0, p1, Landroidx/appcompat/view/menu/md;

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/md;

    iget-object v0, p1, Landroidx/appcompat/view/menu/md;->a:Ljava/lang/Throwable;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/md;->a()Z

    move-result p1

    invoke-virtual {p0, v0, p1}, Landroidx/appcompat/view/menu/g;->I0(Ljava/lang/Throwable;Z)V

    goto :goto_0

    :cond_0
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/g;->J0(Ljava/lang/Object;)V

    :goto_0
    return-void
.end method
