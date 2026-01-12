.class public Landroidx/appcompat/view/menu/ru$c;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/mu;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ru;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ru;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ru;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ru$c;->a:Landroidx/appcompat/view/menu/ru;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public c()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$c;->a:Landroidx/appcompat/view/menu/ru;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ru;->g(Landroidx/appcompat/view/menu/ru;Z)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$c;->a:Landroidx/appcompat/view/menu/ru;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ru;->h(Landroidx/appcompat/view/menu/ru;)Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/mu;

    invoke-interface {v1}, Landroidx/appcompat/view/menu/mu;->c()V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public f()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$c;->a:Landroidx/appcompat/view/menu/ru;

    const/4 v1, 0x1

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ru;->g(Landroidx/appcompat/view/menu/ru;Z)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ru$c;->a:Landroidx/appcompat/view/menu/ru;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ru;->h(Landroidx/appcompat/view/menu/ru;)Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/mu;

    invoke-interface {v1}, Landroidx/appcompat/view/menu/mu;->f()V

    goto :goto_0

    :cond_0
    return-void
.end method
