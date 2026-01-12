.class public final synthetic Landroidx/appcompat/view/menu/as;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/es;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/es;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/as;->m:Landroidx/appcompat/view/menu/es;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/as;->m:Landroidx/appcompat/view/menu/es;

    invoke-static {v0}, Landroidx/appcompat/view/menu/es;->d(Landroidx/appcompat/view/menu/es;)V

    return-void
.end method
