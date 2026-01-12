.class public interface abstract Landroidx/appcompat/view/menu/wd;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public a(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 0

    invoke-static {p1}, Landroidx/appcompat/view/menu/ql0;->b(Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object p1

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/wd;->e(Landroidx/appcompat/view/menu/ql0;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public abstract b(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/al0;
.end method

.method public c(Ljava/lang/Class;)Ljava/util/Set;
    .locals 0

    invoke-static {p1}, Landroidx/appcompat/view/menu/ql0;->b(Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object p1

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/wd;->f(Landroidx/appcompat/view/menu/ql0;)Ljava/util/Set;

    move-result-object p1

    return-object p1
.end method

.method public d(Ljava/lang/Class;)Landroidx/appcompat/view/menu/al0;
    .locals 0

    invoke-static {p1}, Landroidx/appcompat/view/menu/ql0;->b(Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object p1

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/wd;->b(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/al0;

    move-result-object p1

    return-object p1
.end method

.method public e(Landroidx/appcompat/view/menu/ql0;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/wd;->b(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/al0;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {p1}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public f(Landroidx/appcompat/view/menu/ql0;)Ljava/util/Set;
    .locals 0

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/wd;->g(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/al0;

    move-result-object p1

    invoke-interface {p1}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Set;

    return-object p1
.end method

.method public abstract g(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/al0;
.end method
