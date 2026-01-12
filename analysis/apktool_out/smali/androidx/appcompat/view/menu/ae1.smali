.class public final synthetic Landroidx/appcompat/view/menu/ae1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public synthetic a:Landroidx/appcompat/view/menu/hh1;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/hh1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ae1;->a:Landroidx/appcompat/view/menu/hh1;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ae1;->a:Landroidx/appcompat/view/menu/hh1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/hh1;->e()Landroidx/appcompat/view/menu/cg1;

    move-result-object v0

    return-object v0
.end method
