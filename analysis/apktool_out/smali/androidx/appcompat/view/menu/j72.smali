.class public final Landroidx/appcompat/view/menu/j72;
.super Ljava/util/AbstractList;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/y12;
.implements Ljava/util/RandomAccess;


# instance fields
.field public final m:Landroidx/appcompat/view/menu/y12;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y12;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/AbstractList;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/j72;->m:Landroidx/appcompat/view/menu/y12;

    return-void
.end method

.method public static bridge synthetic d(Landroidx/appcompat/view/menu/j72;)Landroidx/appcompat/view/menu/y12;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/j72;->m:Landroidx/appcompat/view/menu/y12;

    return-object p0
.end method


# virtual methods
.method public final b()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/j72;->m:Landroidx/appcompat/view/menu/y12;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/y12;->b()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final synthetic get(I)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/j72;->m:Landroidx/appcompat/view/menu/y12;

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    return-object p1
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/n72;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/n72;-><init>(Landroidx/appcompat/view/menu/j72;)V

    return-object v0
.end method

.method public final j(I)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/j72;->m:Landroidx/appcompat/view/menu/y12;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/y12;->j(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/p72;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/p72;-><init>(Landroidx/appcompat/view/menu/j72;I)V

    return-object v0
.end method

.method public final m()Landroidx/appcompat/view/menu/y12;
    .locals 0

    return-object p0
.end method

.method public final q(Landroidx/appcompat/view/menu/mx1;)V
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final size()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/j72;->m:Landroidx/appcompat/view/menu/y12;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    return v0
.end method
